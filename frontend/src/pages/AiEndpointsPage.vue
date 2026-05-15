<script setup lang="ts">
import { reactive } from 'vue'
import PageSection from '../components/PageSection.vue'
import StatusPill from '../components/StatusPill.vue'
import { useAiEndpointsPage } from '../features/ai-endpoints/useAiEndpointsPage'
import type { AiEndpointItem } from '../services/api'

const state = reactive(useAiEndpointsPage())

function attackRouteForEndpoint(item?: AiEndpointItem | null) {
  if (!item) {
    return { name: 'attack-testing' }
  }
  return {
    name: 'attack-testing',
    query: {
      ai_endpoint_id: String(item.id),
    },
  }
}
</script>

<template>
  <div class="page-grid ai-endpoints-compact-page ai-access-page">
    <section class="ai-access-hero">
      <div class="ai-access-hero-copy">
        <p class="panel-kicker">OpenClaw 接入</p>
        <h2>受保护目标与客户端接入</h2>
      </div>

      <div class="ai-access-stat-grid">
        <article class="ai-access-stat">
          <span>目标总数</span>
          <strong>{{ state.endpointSummary.total }}</strong>
        </article>
        <article class="ai-access-stat">
          <span>已启用保护</span>
          <strong>{{ state.endpointSummary.protected }}</strong>
        </article>
        <article class="ai-access-stat">
          <span>在线 Runtime</span>
          <strong>{{ state.runtimeSummary.runtimes_online }}</strong>
        </article>
        <article class="ai-access-stat warn">
          <span>待处理接入</span>
          <strong>{{ state.runtimeSummary.runtimes_activation_requested + state.runtimeSummary.runtimes_pending }}</strong>
        </article>
      </div>

      <div class="ai-compact-actions">
        <span :class="['ai-compact-sync', `tone-${state.syncState}`]">
          {{ state.syncMessage }}{{ state.lastActionAt ? ` / ${state.lastActionAt}` : '' }}
        </span>
        <button class="ghost-button small" type="button" :disabled="state.loading || state.isBusy" @click="state.refreshList">
          刷新状态
        </button>
        <button
          v-if="state.endpointSummary.cleanup_candidates"
          class="ghost-button small"
          type="button"
          :disabled="state.isBusy"
          @click="state.cleanupEndpointCandidates"
        >
          清理测试目标
        </button>
        <button class="primary-button small" type="button" :disabled="state.isBusy" @click="state.openCreateDrawer">
          新增目标
        </button>
      </div>
    </section>

    <section class="ai-access-flow">
      <article class="ai-access-step ready">
        <span>01</span>
        <strong>创建 OpenClaw 目标</strong>
      </article>
      <article :class="['ai-access-step', { ready: state.selectedEndpoint }]">
        <span>02</span>
        <strong>生成激活码</strong>
      </article>
      <article :class="['ai-access-step', { ready: state.selectedEndpoint?.usage_summary.runtime_count }]">
        <span>03</span>
        <strong>客户端完成接入</strong>
      </article>
      <article :class="['ai-access-step', { ready: state.selectedEndpoint?.usage_summary.runtime_online_count }]">
        <span>04</span>
        <strong>策略与攻击验证</strong>
      </article>
    </section>

    <section class="ai-compact-filterbar ai-access-filterbar">
      <div class="ai-group-tabs compact">
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

      <div class="ai-compact-batch">
        <span>已选 {{ state.selectedCount }}</span>
        <button class="ghost-button small" type="button" :disabled="!state.selectedCount" @click="state.clearSelection">
          清空
        </button>
        <button
          class="ghost-button small"
          type="button"
          :disabled="!state.selectedCount || state.isBusy"
          @click="state.runBatchUpdate('batch-enable', '正在批量启用接入...', { ids: state.selectedIds, enabled: true }, '已批量启用接入')"
        >
          启用
        </button>
        <button
          class="ghost-button small"
          type="button"
          :disabled="!state.selectedCount || state.isBusy"
          @click="state.runBatchUpdate('batch-observe', '正在批量切换到观察模式...', { ids: state.selectedIds, protection_enabled: true, protection_mode: 'observe' }, '已批量切换到观察模式')"
        >
          观察
        </button>
        <button
          class="ghost-button small"
          type="button"
          :disabled="!state.selectedCount || state.isBusy"
          @click="state.runBatchUpdate('batch-enforce', '正在批量切换到拦截模式...', { ids: state.selectedIds, protection_enabled: true, protection_mode: 'enforce' }, '已批量切换到拦截模式')"
        >
          拦截
        </button>
        <button
          class="ghost-button small"
          type="button"
          :disabled="!state.selectedCount || state.isBusy"
          @click="state.runBatchUpdate('batch-off', '正在批量关闭保护...', { ids: state.selectedIds, protection_enabled: false, protection_mode: 'off' }, '已批量关闭保护')"
        >
          关闭保护
        </button>
      </div>
    </section>

    <PageSection eyebrow="接入对象" title="目标列表" :tag="`${state.filteredItems.length} 项`" tone="info">
      <div v-if="state.loading" class="empty-state">
        <p>正在加载目标...</p>
      </div>

      <div v-else-if="state.error" class="empty-state">
        <p>{{ state.error }}</p>
      </div>

      <div v-else-if="!state.filteredItems.length" class="empty-state">
        <p>当前分组下没有目标。</p>
      </div>

      <div v-else class="ai-access-workbench">
        <div class="endpoint-table-list ai-compact-list ai-access-list">
          <article
            v-for="item in state.filteredItems"
            :key="item.id"
            :class="['endpoint-table-row', 'ai-compact-row', 'ai-access-row', { active: state.selectedEndpointId === item.id, selected: state.isSelected(item.id) }]"
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
                  <StatusPill v-if="item.is_default" label="默认" tone="safe" />
                  <StatusPill :label="state.endpointRoleLabel(item)" :tone="state.endpointRoleTone(item)" />
                  <StatusPill :label="state.endpointConnectionLabel(item)" :tone="item.usage_summary.runtime_online_count ? 'safe' : 'info'" />
                </div>
              </div>

              <div class="endpoint-table-meta">
                <span>{{ item.target_label }}</span>
                <span>{{ item.endpoint_group }}</span>
                <span>{{ item.connection_mode === 'runtime_bridge_only' ? 'Runtime 桥接' : '直连 Provider' }}</span>
                <span>{{ state.protectionModeLabels[item.protection_mode] }}</span>
              </div>

              <div class="ai-access-row-next">
                <strong>{{ state.endpointNextStepLabel(item) }}</strong>
              </div>
            </button>

            <div class="endpoint-table-actions ai-compact-row-actions ai-access-row-actions">
              <button class="primary-button small" type="button" :disabled="state.isBusy" @click.stop="state.openEndpoint(item)">
                接入配置
              </button>
              <RouterLink
                class="ghost-button small"
                :to="{ name: 'ai-endpoints-detail', params: { endpointId: String(item.id) } }"
                @click.stop
              >
                治理
              </RouterLink>
              <RouterLink class="ghost-button small" :to="attackRouteForEndpoint(item)" @click.stop>
                攻击测试
              </RouterLink>
            </div>
          </article>
        </div>

        <aside v-if="state.selectedEndpoint" class="ai-access-context-card">
          <div class="ai-access-context-head">
            <div>
              <p class="panel-kicker">当前选择</p>
              <h3>{{ state.selectedEndpoint.display_name }}</h3>
              <span>{{ state.endpointMetaText(state.selectedEndpoint) }}</span>
            </div>
            <StatusPill :label="state.endpointStatusLabel(state.selectedEndpoint)" :tone="state.endpointTone(state.selectedEndpoint)" />
          </div>

          <div class="ai-access-next-box">
            <span>建议下一步</span>
            <strong>{{ state.endpointNextStepLabel(state.selectedEndpoint) }}</strong>
          </div>

          <div class="ai-access-context-metrics">
            <article>
              <span>Runtime</span>
              <strong>{{ state.selectedEndpoint.usage_summary.runtime_count }}</strong>
              <small>在线 {{ state.selectedEndpoint.usage_summary.runtime_online_count }}</small>
            </article>
            <article>
              <span>激活码</span>
              <strong>{{ state.selectedEndpoint.usage_summary.token_count }}</strong>
              <small>待处理 {{ state.endpointRuntimeAttentionCount(state.selectedEndpoint) }}</small>
            </article>
            <article>
              <span>任务</span>
              <strong>{{ state.selectedEndpoint.usage_summary.task_count }}</strong>
              <small>运行中 {{ state.selectedEndpoint.usage_summary.active_task_count }}</small>
            </article>
          </div>

          <div class="ai-access-context-actions">
            <button class="primary-button small" type="button" :disabled="state.isBusy" @click="state.openEndpoint(state.selectedEndpoint)">
              打开接入配置
            </button>
            <button class="ghost-button small" type="button" :disabled="state.isBusy" @click="state.testEndpoint(state.selectedEndpoint)">
              测试连通
            </button>
            <RouterLink
              class="ghost-button small"
              :to="{ name: 'ai-endpoints-detail', params: { endpointId: String(state.selectedEndpoint.id) } }"
            >
              Skill / 目录 / 研判
            </RouterLink>
            <RouterLink
              class="ghost-button small"
              :to="{ name: 'ai-endpoints-mcp-policy', params: { endpointId: String(state.selectedEndpoint.id) } }"
            >
              MCP 策略
            </RouterLink>
            <RouterLink class="ghost-button small" :to="attackRouteForEndpoint(state.selectedEndpoint)">
              攻击测试
            </RouterLink>
          </div>
        </aside>
      </div>
    </PageSection>

    <section v-if="state.testOutput" class="ai-compact-result">
      <div>
        <strong>最近一次连通结果</strong>
        <p>{{ state.testOutput }}</p>
      </div>
      <div v-if="state.testUsage" class="token-list">
        <span v-for="[key, value] in Object.entries(state.testUsage)" :key="key" class="token-chip">
          {{ key }}: {{ String(value) }}
        </span>
      </div>
    </section>
  </div>
</template>
