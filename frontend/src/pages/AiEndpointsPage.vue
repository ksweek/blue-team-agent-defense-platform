<script setup lang="ts">
import { reactive } from 'vue'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import TopStatusRail from '../components/TopStatusRail.vue'
import AiEndpointDrawer from '../features/ai-endpoints/components/AiEndpointDrawer.vue'
import { useAiEndpointsPage } from '../features/ai-endpoints/useAiEndpointsPage'

const state = reactive(useAiEndpointsPage())
</script>

<template>
  <div class="page-grid">
    <TopStatusRail
      title="AI 目标"
      summary="模型接入、防护绑定与在线 Runtime 纳管"
      :items="state.topRailItems"
      :status-label="state.syncState === 'error' ? '异常' : state.syncState === 'saved' ? '已同步' : state.syncState === 'saving' ? '处理中' : '就绪'"
      :status-tone="state.syncState === 'error' ? 'danger' : state.syncState === 'saved' ? 'safe' : state.syncState === 'saving' ? 'warn' : 'info'"
      :meta="`${state.syncMessage}${state.lastActionAt ? ` / ${state.lastActionAt}` : ''}`"
    >
      <template #actions>
        <button class="ghost-button small" type="button" :disabled="state.loading || state.isBusy" @click="state.refreshList">
          刷新
        </button>
        <button
          v-if="state.endpointSummary.cleanup_candidates"
          class="ghost-button small"
          type="button"
          :disabled="state.isBusy"
          @click="state.cleanupEndpointCandidates"
        >
          清理测试端点
        </button>
        <button class="primary-button small" type="button" :disabled="state.isBusy" @click="state.openCreateDrawer">
          新增目标
        </button>
      </template>
    </TopStatusRail>

    <section class="ai-route-strip ai-endpoint-banner">
      <div class="ai-route-copy">
        <strong>{{ state.selectedEndpoint ? `当前目标：${state.selectedEndpoint.display_name}` : '尚未选择 AI 目标' }}</strong>
        <p class="card-subtitle">
          {{
            state.selectedEndpoint
              ? `${state.endpointSummaryText(state.selectedEndpoint)} / ${state.endpointMetaText(state.selectedEndpoint)}`
              : '先新增真实模型端点，再绑定 Runtime 或注册码。'
          }}
        </p>
      </div>
      <div class="table-actions wrap">
        <button
          class="ghost-button small"
          type="button"
          :disabled="!state.selectedCount || state.isBusy"
          @click="state.runBatchUpdate('batch-enable', '正在批量启用接入...', { ids: state.selectedIds, enabled: true }, '已批量启用接入')"
        >
          批量启用
        </button>
        <button
          class="ghost-button small"
          type="button"
          :disabled="!state.selectedCount || state.isBusy"
          @click="state.runBatchUpdate('batch-observe', '正在批量切到观察模式...', { ids: state.selectedIds, protection_enabled: true, protection_mode: 'observe' }, '已批量切到观察模式')"
        >
          批量观察
        </button>
        <button
          class="ghost-button small"
          type="button"
          :disabled="!state.selectedCount || state.isBusy"
          @click="state.runBatchUpdate('batch-enforce', '正在批量切到拦截模式...', { ids: state.selectedIds, protection_enabled: true, protection_mode: 'enforce' }, '已批量切到拦截模式')"
        >
          批量拦截
        </button>
      </div>
    </section>

    <div class="ai-endpoint-console ai-endpoint-console-dense">
      <div class="ai-endpoint-left">
        <PageSection eyebrow="目标清单" title="受保护 AI 目标" :tag="`${state.filteredItems.length} 项`" tone="info">
          <template #toolbar>
            <div class="ai-group-tabs">
              <button
                v-for="option in state.groupOptions"
                :key="option.key"
                :class="['ai-group-tab', { active: state.activeGroup === option.key }]"
                type="button"
                @click="state.activeGroup = option.key"
              >
                <strong>{{ option.label }}</strong>
                <span>{{ option.count }}</span>
              </button>
            </div>

            <div class="section-toolbar endpoint-section-toolbar">
              <div class="section-toolbar-copy">
                <h4>分组与批量动作</h4>
                <p class="section-toolbar-meta">
                  {{ state.activeGroup === 'all' ? '全部分组' : state.activeGroup }} / 已选 {{ state.selectedCount }} 项
                </p>
              </div>
              <div class="table-actions wrap">
                <button class="ghost-button small" type="button" :disabled="!state.selectedCount" @click="state.clearSelection">
                  清空选择
                </button>
                <button
                  class="ghost-button small"
                  type="button"
                  :disabled="!state.selectedCount || state.isBusy"
                  @click="state.runBatchUpdate('batch-off', '正在批量关闭防护...', { ids: state.selectedIds, protection_enabled: false, protection_mode: 'off' }, '已批量关闭防护')"
                >
                  批量关闭防护
                </button>
              </div>
            </div>
          </template>

          <div v-if="state.loading" class="empty-state">
            <p>正在加载 AI 目标...</p>
          </div>

          <div v-else-if="state.error" class="empty-state">
            <p>{{ state.error }}</p>
          </div>

          <div v-else-if="!state.filteredItems.length" class="empty-state">
            <p>当前分组下没有 AI 目标。</p>
          </div>

          <div v-else class="endpoint-table-list">
            <article
              v-for="item in state.filteredItems"
              :key="item.id"
              :class="['endpoint-table-row', { active: state.selectedEndpointId === item.id, selected: state.isSelected(item.id) }]"
            >
              <label class="selection-toggle endpoint-row-toggle" @click.stop>
                <input
                  class="row-selector"
                  :checked="state.isSelected(item.id)"
                  type="checkbox"
                  @change="state.handleSelectionChange(item.id, $event)"
                />
              </label>

              <button class="endpoint-table-main" type="button" @click="state.selectEndpoint(item.id)">
                <div class="endpoint-table-head">
                  <div class="endpoint-table-title">
                    <strong>{{ item.display_name }}</strong>
                    <span class="code-inline">{{ item.endpoint_key }}</span>
                  </div>
                  <div class="sample-preview-tags">
                    <StatusPill v-if="item.is_default" label="默认路由" tone="safe" />
                    <StatusPill
                      v-if="item.is_demo_endpoint"
                      :label="item.is_cleanup_candidate ? '可清理测试端点' : '测试端点'"
                      :tone="item.is_cleanup_candidate ? 'warn' : 'info'"
                    />
                    <StatusPill :label="state.endpointStatusLabel(item)" :tone="state.endpointTone(item)" />
                  </div>
                </div>

                <div class="endpoint-table-meta">
                  <span>{{ state.endpointSummaryText(item) }}</span>
                  <span>{{ item.endpoint_group }}</span>
                  <span>{{ state.endpointMetaText(item) }}</span>
                </div>

                <div class="endpoint-table-stats">
                  <span>Runtime {{ item.usage_summary.runtime_count }}</span>
                  <span>在线 {{ item.usage_summary.runtime_online_count }}</span>
                  <span>注册码 {{ item.usage_summary.token_count }}</span>
                  <span>任务 {{ item.usage_summary.active_task_count }} / {{ item.usage_summary.task_count }}</span>
                </div>
              </button>

              <div class="endpoint-table-actions">
                <button class="ghost-button small" type="button" :disabled="state.isBusy" @click.stop="state.testEndpoint(item)">
                  测试
                </button>
                <button class="ghost-button small" type="button" :disabled="state.isBusy" @click.stop="state.openEndpoint(item)">
                  配置
                </button>
                <button
                  class="ghost-button small"
                  type="button"
                  :disabled="item.is_default || state.isBusy"
                  @click.stop="state.setEndpointDefault(item)"
                >
                  默认
                </button>
              </div>
            </article>
          </div>
        </PageSection>
      </div>

      <div class="ai-endpoint-right">
        <PageSection
          eyebrow="当前目标"
          title="接入与防护"
          :tag="state.selectedEndpoint ? state.endpointStatusLabel(state.selectedEndpoint) : '未选择'"
          :tone="state.selectedEndpoint ? state.endpointTone(state.selectedEndpoint) : 'info'"
        >
          <div v-if="state.selectedEndpoint" class="ai-endpoint-summary-card">
            <div class="ai-endpoint-summary-head">
              <div class="ai-endpoint-summary-copy">
                <h4>{{ state.selectedEndpoint.display_name }}</h4>
                <p>{{ state.endpointSummaryText(state.selectedEndpoint) }}</p>
              </div>
              <div class="sample-preview-tags">
                <StatusPill :label="state.selectedEndpoint.enabled ? '已启用' : '已停用'" :tone="state.selectedEndpoint.enabled ? 'safe' : 'info'" />
                <StatusPill :label="state.bindingStateLabel({ binding_state: 'bound' })" tone="safe" />
              </div>
            </div>

            <div class="settings-snapshot-list">
              <div class="settings-snapshot-row">
                <div class="settings-snapshot-copy">
                  <h4>路由与模型</h4>
                  <p>{{ state.selectedEndpoint.endpoint_group }} / {{ state.selectedEndpoint.model_name }}</p>
                </div>
                <p class="settings-snapshot-value">{{ state.providerLabels[state.selectedEndpoint.provider_type] }}</p>
              </div>

              <div class="settings-snapshot-row">
                <div class="settings-snapshot-copy">
                  <h4>默认路由</h4>
                  <p>{{ state.selectedEndpoint.is_default ? '未显式指定 endpoint_key 时会回退到这里。' : '当前不是默认回退目标。' }}</p>
                </div>
                <p class="settings-snapshot-value">{{ state.selectedEndpoint.is_default ? '是' : '否' }}</p>
              </div>

              <div class="settings-snapshot-row">
                <div class="settings-snapshot-copy">
                  <h4>防护模式</h4>
                  <p>{{ state.selectedEndpoint.protection_enabled ? '请求会先走执行前授权与策略判定。' : '当前仅作为路由目标，不执行前置防护。' }}</p>
                </div>
                <p class="settings-snapshot-value">{{ state.protectionModeLabels[state.selectedEndpoint.protection_mode] }}</p>
              </div>

              <div class="settings-snapshot-row">
                <div class="settings-snapshot-copy">
                  <h4>上游地址</h4>
                  <p>{{ state.endpointMetaText(state.selectedEndpoint) }}</p>
                </div>
                <p class="settings-snapshot-value">
                  Runtime {{ state.selectedEndpoint.usage_summary.runtime_count }} / Token {{ state.selectedEndpoint.usage_summary.token_count }}
                </p>
              </div>

              <div class="settings-snapshot-row">
                <div class="settings-snapshot-copy">
                  <h4>最近活跃</h4>
                  <p>{{ state.selectedEndpoint.usage_summary.last_runtime_seen_at || '暂无在线心跳' }}</p>
                </div>
                <p class="settings-snapshot-value">在线 {{ state.selectedEndpoint.usage_summary.runtime_online_count }}</p>
              </div>
            </div>

            <div class="table-actions wrap">
              <button class="primary-button small" type="button" :disabled="state.isBusy" @click="state.openEndpoint(state.selectedEndpoint)">
                打开配置
              </button>
              <button class="ghost-button small" type="button" :disabled="state.isBusy" @click="state.testEndpoint(state.selectedEndpoint)">
                连通测试
              </button>
              <button class="ghost-button small" type="button" :disabled="state.selectedEndpoint.is_default || state.isBusy" @click="state.setEndpointDefault(state.selectedEndpoint)">
                设为默认
              </button>
              <button class="ghost-button small" type="button" :disabled="state.isBusy" @click="state.toggleEndpointEnabled(state.selectedEndpoint)">
                {{ state.selectedEndpoint.enabled ? '停用接入' : '启用接入' }}
              </button>
            </div>

            <div class="table-actions wrap">
              <button class="ghost-button small" type="button" :disabled="state.isBusy" @click="state.setEndpointProtectionMode(state.selectedEndpoint, 'enforce')">
                拦截模式
              </button>
              <button class="ghost-button small" type="button" :disabled="state.isBusy" @click="state.setEndpointProtectionMode(state.selectedEndpoint, 'observe')">
                观察模式
              </button>
              <button class="ghost-button small" type="button" :disabled="state.isBusy" @click="state.setEndpointProtectionMode(state.selectedEndpoint, 'off')">
                关闭防护
              </button>
              <button class="ghost-button small danger" type="button" :disabled="state.isBusy" @click="state.deleteEndpoint(state.selectedEndpoint)">
                删除目标
              </button>
            </div>

            <div v-if="state.selectedEndpoint.is_demo_endpoint" :class="['endpoint-inline-alert', state.selectedEndpoint.is_cleanup_candidate ? 'tone-warn' : 'tone-info']">
              <div class="endpoint-inline-alert-copy">
                <strong>{{ state.selectedEndpoint.is_cleanup_candidate ? '测试端点候选' : '测试端点仍被任务引用' }}</strong>
                <p>
                  {{
                    state.selectedEndpoint.is_cleanup_candidate
                      ? '这个目标符合“测试 / 冒烟端点”特征，可直接清理并释放已绑定对象。'
                      : `这个目标仍被 ${state.selectedEndpoint.usage_summary.active_task_count} 个活跃任务引用，暂时不能直接删除。`
                  }}
                </p>
              </div>
              <button
                v-if="state.selectedEndpoint.is_cleanup_candidate"
                class="ghost-button small"
                type="button"
                :disabled="state.isBusy"
                @click="state.deleteEndpoint(state.selectedEndpoint)"
              >
                立即清理
              </button>
            </div>
          </div>

          <div v-else class="empty-state">
            <p>当前没有选中的 AI 目标。可以先新增一个真实上游端点。</p>
          </div>
        </PageSection>

        <PageSection eyebrow="绑定态" title="已绑定 Runtime" :tag="`${state.selectedEndpointRuntimes.length} 项`" tone="warn">
          <div v-if="!state.selectedEndpoint" class="empty-state">
            <p>先选中一个 AI 目标，才能查看它名下的 Runtime。</p>
          </div>
          <div v-else-if="!state.selectedEndpointRuntimes.length" class="empty-state">
            <p>这个目标下还没有已绑定 Runtime。</p>
          </div>
          <div v-else class="endpoint-detail-list">
            <article v-for="item in state.selectedEndpointRuntimes" :key="item.id" class="endpoint-detail-row">
              <div class="endpoint-detail-main">
                <div class="endpoint-detail-head">
                  <strong>{{ item.display_name }}</strong>
                  <div class="sample-preview-tags">
                    <StatusPill :label="state.runtimeStatusLabel(item)" :tone="state.runtimeStatusTone(item)" />
                    <StatusPill :label="item.is_online ? '在线' : '离线'" :tone="item.is_online ? 'safe' : 'info'" />
                  </div>
                </div>
                <p>{{ item.status_summary }} / {{ item.hostname || '未上报主机名' }}</p>
                <div class="endpoint-detail-meta">
                  <span>{{ item.runtime_type }}</span>
                  <span>{{ item.last_seen_at || '暂无心跳' }}</span>
                  <span>{{ item.ip_addresses.join(' / ') || '无 IP' }}</span>
                </div>
              </div>
              <div class="endpoint-detail-actions">
                <button
                  v-if="item.status === 'pending' || item.status === 'approved'"
                  class="ghost-button small"
                  type="button"
                  :disabled="state.isBusy"
                  @click="state.approveRuntime(item)"
                >
                  批准
                </button>
                <button class="ghost-button small" type="button" :disabled="state.isBusy" @click="state.unbindRuntime(item)">
                  解绑
                </button>
                <button
                  v-if="item.status === 'pending' || item.status === 'approved'"
                  class="ghost-button small"
                  type="button"
                  :disabled="state.isBusy"
                  @click="state.rejectRuntime(item)"
                >
                  拒绝
                </button>
                <button
                  v-else
                  class="ghost-button small"
                  type="button"
                  :disabled="state.isBusy"
                  @click="state.revokeRuntime(item)"
                >
                  撤销
                </button>
              </div>
            </article>
          </div>
        </PageSection>

        <PageSection eyebrow="绑定态" title="已绑定注册码" :tag="`${state.selectedEndpointTokens.length} 项`" tone="info">
          <div v-if="!state.selectedEndpoint" class="empty-state">
            <p>先选中一个 AI 目标，才能查看它名下的注册码。</p>
          </div>
          <div v-else-if="!state.selectedEndpointTokens.length" class="empty-state">
            <p>这个目标下还没有已绑定注册码。</p>
          </div>
          <div v-else class="endpoint-detail-list">
            <article v-for="item in state.selectedEndpointTokens" :key="item.id" class="endpoint-detail-row">
              <div class="endpoint-detail-main">
                <div class="endpoint-detail-head">
                  <strong>{{ item.token_label }}</strong>
                  <div class="sample-preview-tags">
                    <StatusPill :label="state.tokenStatusLabel(item)" :tone="state.tokenStatusTone(item)" />
                    <StatusPill :label="state.bindingStateLabel(item)" :tone="state.bindingStateTone(item)" />
                  </div>
                </div>
                <p>{{ item.runtime_type }} / {{ item.token_hint }}</p>
                <div class="endpoint-detail-meta">
                  <span>可用 {{ item.remaining_uses }}</span>
                  <span>已用 {{ item.used_count }}</span>
                  <span>{{ item.expires_at || '不过期' }}</span>
                </div>
              </div>
              <div class="endpoint-detail-actions">
                <button class="ghost-button small" type="button" :disabled="state.isBusy" @click="state.unbindToken(item)">
                  解绑
                </button>
              </div>
            </article>
          </div>
        </PageSection>

        <PageSection eyebrow="待处理接入" title="未绑定对象" :tag="`${state.unboundRuntimes.length + state.unboundTokens.length} 项`" tone="warn">
          <div class="endpoint-subsection">
            <div class="endpoint-subsection-head">
              <h4>未绑定 Runtime</h4>
              <span>{{ state.unboundRuntimes.length }} 项</span>
            </div>
            <div v-if="!state.unboundRuntimes.length" class="token-empty">没有未绑定 Runtime。</div>
            <div v-else class="endpoint-detail-list">
              <article v-for="item in state.unboundRuntimes" :key="item.id" class="endpoint-detail-row">
                <div class="endpoint-detail-main">
                  <div class="endpoint-detail-head">
                    <strong>{{ item.display_name }}</strong>
                    <div class="sample-preview-tags">
                      <StatusPill :label="state.runtimeStatusLabel(item)" :tone="state.runtimeStatusTone(item)" />
                      <StatusPill :label="state.bindingStateLabel(item)" :tone="state.bindingStateTone(item)" />
                    </div>
                  </div>
                  <p>{{ item.status_summary }} / {{ item.hostname || '未上报主机名' }}</p>
                  <div class="endpoint-detail-meta">
                    <span>{{ item.runtime_type }}</span>
                    <span>{{ item.last_seen_at || '暂无心跳' }}</span>
                    <span>{{ item.ip_addresses.join(' / ') || '无 IP' }}</span>
                  </div>
                </div>
                <div class="endpoint-detail-actions">
                  <button class="ghost-button small" type="button" :disabled="!state.selectedEndpoint || state.isBusy" @click="state.bindRuntimeToSelected(item)">
                    绑定到当前
                  </button>
                  <button
                    v-if="item.status === 'pending' || item.status === 'approved'"
                    class="ghost-button small"
                    type="button"
                    :disabled="state.isBusy"
                    @click="state.selectedEndpoint ? state.approveAndBindRuntime(item) : state.approveRuntime(item)"
                  >
                    {{ state.selectedEndpoint ? '绑定并批准' : '批准' }}
                  </button>
                  <button
                    v-if="item.status === 'pending' || item.status === 'approved'"
                    class="ghost-button small"
                    type="button"
                    :disabled="state.isBusy"
                    @click="state.rejectRuntime(item)"
                  >
                    拒绝
                  </button>
                  <button
                    v-else
                    class="ghost-button small"
                    type="button"
                    :disabled="state.isBusy"
                    @click="state.revokeRuntime(item)"
                  >
                    撤销
                  </button>
                </div>
              </article>
            </div>
          </div>

          <div class="endpoint-subsection">
            <div class="endpoint-subsection-head">
              <h4>未绑定注册码</h4>
              <span>{{ state.unboundTokens.length }} 项</span>
            </div>
            <div v-if="!state.unboundTokens.length" class="token-empty">没有未绑定注册码。</div>
            <div v-else class="endpoint-detail-list">
              <article v-for="item in state.unboundTokens" :key="item.id" class="endpoint-detail-row">
                <div class="endpoint-detail-main">
                  <div class="endpoint-detail-head">
                    <strong>{{ item.token_label }}</strong>
                    <div class="sample-preview-tags">
                      <StatusPill :label="state.tokenStatusLabel(item)" :tone="state.tokenStatusTone(item)" />
                      <StatusPill :label="state.bindingStateLabel(item)" :tone="state.bindingStateTone(item)" />
                    </div>
                  </div>
                  <p>{{ item.runtime_type }} / {{ item.token_hint }}</p>
                  <div class="endpoint-detail-meta">
                    <span>可用 {{ item.remaining_uses }}</span>
                    <span>已用 {{ item.used_count }}</span>
                    <span>{{ item.expires_at || '不过期' }}</span>
                  </div>
                </div>
                <div class="endpoint-detail-actions">
                  <button class="ghost-button small" type="button" :disabled="!state.selectedEndpoint || state.isBusy" @click="state.bindTokenToSelected(item)">
                    绑定到当前
                  </button>
                </div>
              </article>
            </div>
          </div>
        </PageSection>

        <PageSection eyebrow="客户端接入" title="注册码与接入步骤" tag="审批链" tone="warn">
          <div class="ai-runtime-token-form">
            <input
              v-model="state.runtimeTokenLabel"
              class="text-input"
              type="text"
              placeholder="注册码名称"
            />
            <input
              v-model="state.runtimeTokenType"
              class="text-input"
              type="text"
              placeholder="runtime 类型，例如 agent"
            />
            <input
              v-model.number="state.runtimeTokenUsageLimit"
              class="text-input"
              type="number"
              min="1"
              placeholder="使用次数"
            />
            <input
              v-model="state.runtimeTokenExpiresAt"
              class="text-input"
              type="datetime-local"
              placeholder="过期时间"
            />
            <button class="primary-button small" type="button" :disabled="!state.selectedEndpoint || state.isBusy" @click="state.createRuntimeToken">
              生成注册码
            </button>
          </div>

          <div class="card-subtitle">
            {{ state.selectedEndpoint ? `将绑定到 ${state.selectedEndpoint.display_name}` : '先选中一个 AI 目标，再生成注册码。' }}
          </div>

          <div v-if="state.latestEnrollmentToken" class="endpoint-token-result">
            <div class="endpoint-token-result-head">
              <strong>最新注册码</strong>
              <div class="table-actions">
                <button class="ghost-button small" type="button" @click="state.copyText(state.latestEnrollmentToken, '已复制注册码')">
                  复制
                </button>
              </div>
            </div>
            <pre class="ai-access-sample">{{ state.latestEnrollmentToken }}</pre>
            <ol class="ai-access-step-list">
              <li v-for="step in state.latestEnrollmentSteps" :key="step">{{ step }}</li>
            </ol>
          </div>
        </PageSection>

        <PageSection eyebrow="接入说明" title="统一代理入口" tag="默认收起" tone="info" collapsible :defaultCollapsed="true">
          <div v-if="state.selectedEndpointIntegration" class="endpoint-guide-stack">
            <div class="endpoint-inline-alert tone-info">
              <div class="endpoint-inline-alert-copy">
                <strong>当前说明</strong>
                <p>{{ state.selectedEndpointIntegration.protection_summary }}</p>
              </div>
            </div>

            <div class="settings-snapshot-list">
              <div class="settings-snapshot-row">
                <div class="settings-snapshot-copy">
                  <h4>HTTP 代理入口</h4>
                  <p>{{ state.selectedEndpointIntegration.default_route_summary }}</p>
                </div>
                <p class="settings-snapshot-value">
                  <button class="ghost-button small" type="button" @click="state.copyText(state.selectedEndpointIntegration.gateway_base_path, '已复制 HTTP 入口')">
                    {{ state.selectedEndpointIntegration.gateway_base_path }}
                  </button>
                </p>
              </div>

              <div class="settings-snapshot-row">
                <div class="settings-snapshot-copy">
                  <h4>WebSocket 入口</h4>
                  <p>适合 stream=true 或长连接在线代理场景。</p>
                </div>
                <p class="settings-snapshot-value">
                  <button class="ghost-button small" type="button" @click="state.copyText(state.selectedEndpointIntegration.gateway_ws_base_path, '已复制 WebSocket 入口')">
                    {{ state.selectedEndpointIntegration.gateway_ws_base_path }}
                  </button>
                </p>
              </div>
            </div>

            <div class="endpoint-guide-grid">
              <section class="endpoint-guide-card">
                <div class="endpoint-subsection-head">
                  <h4>路由选择</h4>
                </div>
                <article
                  v-for="selector in state.selectedEndpointIntegration.route_selector_items"
                  :key="selector.key"
                  class="endpoint-guide-row"
                >
                  <div class="endpoint-detail-main">
                    <strong>{{ selector.label }}</strong>
                    <p>{{ selector.detail }}</p>
                  </div>
                  <button class="ghost-button small" type="button" @click="state.copyText(selector.value, `已复制 ${selector.label}`)">
                    {{ selector.value }}
                  </button>
                </article>
              </section>

              <section class="endpoint-guide-card">
                <div class="endpoint-subsection-head">
                  <h4>认证方式</h4>
                </div>
                <article
                  v-for="auth in state.selectedEndpointIntegration.auth_modes"
                  :key="auth.key"
                  class="endpoint-guide-row"
                >
                  <div class="endpoint-detail-main">
                    <strong>{{ auth.label }}</strong>
                    <p>{{ auth.summary }}</p>
                  </div>
                  <button class="ghost-button small" type="button" @click="state.copyText(`${auth.header_name}: ${auth.header_value}`, `已复制 ${auth.label}`)">
                    {{ auth.header_name }}
                  </button>
                </article>
              </section>
            </div>

            <div v-if="state.selectedEndpointIntegration.access_modes[0]" class="endpoint-token-result">
              <div class="endpoint-token-result-head">
                <strong>{{ state.selectedEndpointIntegration.access_modes[0].label }}</strong>
                <button
                  class="ghost-button small"
                  type="button"
                  @click="state.copyText(state.selectedEndpointIntegration.access_modes[0].sample_lines.join('\n'), '已复制接入示例')"
                >
                  复制示例
                </button>
              </div>
              <pre class="ai-access-sample">{{ state.selectedEndpointIntegration.access_modes[0].sample_lines.join('\n') }}</pre>
            </div>
          </div>
          <div v-else class="empty-state">
            <p>先选中一个 AI 目标，才能查看代理接入说明。</p>
          </div>
        </PageSection>
      </div>
    </div>

    <AiEndpointDrawer
      :open="state.drawerOpen"
      :mode="state.drawerMode"
      :title="state.drawerTitle"
      :summary="state.drawerSummary"
      :busy="state.isBusy"
      :form="state.drawerForm"
      :selected-endpoint="state.selectedEndpoint"
      :test-output="state.testOutput"
      :test-usage="state.testUsage"
      @close="state.closeDrawer"
      @save="state.saveDrawer"
      @test="state.selectedEndpoint && state.testEndpoint(state.selectedEndpoint)"
      @delete="state.selectedEndpoint && state.deleteEndpoint(state.selectedEndpoint)"
    />
  </div>
</template>
