<script setup lang="ts">
import type { AiEndpointItem } from '../../../services/api'
import StatusPill from '../../../components/StatusPill.vue'
import { PROTECTION_MODE_OPTIONS, TARGET_TYPE_OPTIONS } from '../constants'
import type { EndpointForm, EndpointSecretDraft } from '../useAiEndpointsPage'

const props = defineProps<{
  mode: 'create' | 'detail'
  busy: boolean
  form: EndpointForm
  selectedEndpoint: AiEndpointItem | null
  testOutput: string
  testUsage: Record<string, unknown> | null
}>()

defineEmits<{
  save: []
  test: []
  delete: []
}>()

function secretKeyLabel(path: string) {
  const cleaned = path.replace(/\[\d+\]$/g, '')
  const segments = cleaned.split('.').filter(Boolean)
  return segments[segments.length - 1] || path
}

function isDraftSecret(item: EndpointSecretDraft) {
  return item.masked_value === '待新增'
}

function addSecretDraft() {
  const path = props.form.new_secret_path.trim()
  const value = props.form.new_secret_value.trim()
  if (!path || !value) {
    return
  }

  const existing = props.form.config_secret_items.find((item) => item.path === path)
  if (existing) {
    existing.next_value = value
    existing.remove = false
  } else {
    props.form.config_secret_items = [
      ...props.form.config_secret_items,
      {
        path,
        key: secretKeyLabel(path),
        masked_value: '待新增',
        value_type: 'string',
        next_value: value,
        remove: false,
      },
    ]
  }

  props.form.new_secret_path = ''
  props.form.new_secret_value = ''
}

function toggleSecretRemoval(item: EndpointSecretDraft) {
  item.remove = !item.remove
}

function discardSecretDraft(item: EndpointSecretDraft) {
  props.form.config_secret_items = props.form.config_secret_items.filter((entry) => entry.path !== item.path)
}

function secretValueTypeLabel(item: EndpointSecretDraft) {
  if (item.value_type === 'object') return '对象'
  if (item.value_type === 'array') return '数组'
  if (item.value_type === 'number') return '数字'
  if (item.value_type === 'boolean') return '布尔'
  if (item.value_type === 'null') return '空值'
  return '字符串'
}

function selectedTargetLabel() {
  return (
    props.selectedEndpoint?.target_label ||
    TARGET_TYPE_OPTIONS.find((item) => item.value === props.form.target_type)?.label ||
    'OpenClaw 受保护目标'
  )
}

function selectedConnectionModeLabel() {
  if (props.selectedEndpoint?.connection_mode === 'runtime_bridge_only') {
    return 'Runtime 桥接'
  }
  if (props.selectedEndpoint?.connection_mode === 'direct_provider') {
    return '直连 Provider'
  }
  return 'Runtime 桥接'
}
</script>

<template>
  <div class="ai-drawer-form-stack">
    <section class="ai-drawer-form-section">
      <div class="ai-drawer-form-header">
        <strong>基本信息</strong>
      </div>
      <div class="ai-drawer-form-list settings-form-list settings-form-list-compact">
        <div class="settings-form-row settings-form-row-compact">
          <div class="settings-form-copy">
            <h4>目标标识</h4>
          </div>
          <div class="settings-form-control">
            <input
              v-model="form.endpoint_key"
              class="text-input settings-form-input"
              type="text"
              placeholder="openclaw-prod-01"
            />
          </div>
        </div>

        <div class="settings-form-row settings-form-row-compact">
          <div class="settings-form-copy">
            <h4>显示名称</h4>
          </div>
          <div class="settings-form-control">
            <input
              v-model="form.display_name"
              class="text-input settings-form-input"
              type="text"
              placeholder="生产 OpenClaw 客户端"
            />
          </div>
        </div>

        <div class="settings-form-row settings-form-row-compact">
          <div class="settings-form-copy">
            <h4>分组</h4>
          </div>
          <div class="settings-form-control">
            <input
              v-model="form.endpoint_group"
              class="text-input settings-form-input"
              type="text"
              placeholder="production"
            />
          </div>
        </div>

        <div class="settings-form-row settings-form-row-compact">
          <div class="settings-form-copy">
            <h4>说明</h4>
          </div>
          <div class="settings-form-control">
            <input
              v-model="form.description"
              class="text-input settings-form-input"
              type="text"
              placeholder="用于接入并保护 OpenClaw 的运行时客户端"
            />
          </div>
        </div>
      </div>
    </section>

    <section class="ai-drawer-form-section">
      <div class="ai-drawer-form-header">
        <strong>接入方式</strong>
      </div>
      <div class="ai-drawer-form-list settings-form-list settings-form-list-compact">
        <div class="settings-form-row settings-form-row-compact">
          <div class="settings-form-copy">
            <h4>目标类型</h4>
          </div>
          <div class="settings-form-control">
            <select
              v-model="form.target_type"
              class="select-input settings-form-select"
              :disabled="TARGET_TYPE_OPTIONS.length <= 1"
            >
              <option v-for="option in TARGET_TYPE_OPTIONS" :key="option.value" :value="option.value">
                {{ option.label }}
              </option>
            </select>
          </div>
        </div>

        <div class="endpoint-target-note">
          <div class="endpoint-target-note-copy">
            <strong>{{ selectedTargetLabel() }}</strong>
            <p>平台只管理目标身份、保护策略、Runtime 绑定、Skill 扫描和后续扩展配置。</p>
            <p>OpenClaw 的上游地址、gateway token 和本地长期凭据只在客户端脚本中填写或复用，不在平台页面暴露。</p>
          </div>
          <div class="sample-preview-tags">
            <StatusPill label="当前仅保留 OpenClaw 格式" tone="info" />
            <StatusPill v-if="selectedEndpoint" :label="selectedConnectionModeLabel()" tone="safe" />
          </div>
        </div>

        <details class="endpoint-advanced-card">
          <summary class="endpoint-advanced-summary">
            <strong>高级配置</strong>
            <span>仅在后续扩展其它 Agent 适配时使用</span>
          </summary>

          <div class="endpoint-advanced-content">
            <div class="settings-form-row settings-form-row-compact settings-form-row-nested endpoint-json-row">
              <div class="settings-form-copy">
                <h4>公开配置 JSON</h4>
                <p>放非敏感扩展参数，例如额外标签、运行时元数据或未来兼容字段。</p>
              </div>
              <div class="settings-form-control endpoint-json-control">
                <textarea
                  v-model="form.config_public_text"
                  class="endpoint-json-input"
                  rows="8"
                  spellcheck="false"
                />
              </div>
            </div>

            <div class="endpoint-secret-panel">
              <div class="endpoint-secret-head">
                <div>
                  <h4>隐藏敏感参数</h4>
                  <p class="endpoint-inline-note">默认 OpenClaw 保护流程不需要平台保存这些值，仅保留扩展能力。</p>
                </div>
                <StatusPill
                  :label="`${form.config_secret_items.length} 项`"
                  :tone="form.config_secret_items.length ? 'warn' : 'info'"
                />
              </div>

              <div v-if="form.config_secret_items.length" class="endpoint-secret-list">
                <article
                  v-for="item in form.config_secret_items"
                  :key="item.path"
                  :class="['endpoint-secret-row', { removed: item.remove }]"
                >
                  <div class="endpoint-secret-row-head">
                    <div class="endpoint-secret-row-copy">
                      <strong>{{ item.path }}</strong>
                      <p>{{ isDraftSecret(item) ? '这是待写入的新敏感配置，保存后只显示掩码。' : `当前值: ${item.masked_value}` }}</p>
                    </div>
                    <div class="endpoint-secret-row-meta">
                      <StatusPill :label="secretValueTypeLabel(item)" tone="info" />
                      <StatusPill v-if="item.remove" label="待删除" tone="danger" />
                      <button
                        v-if="isDraftSecret(item)"
                        class="ghost-button small"
                        type="button"
                        @click="discardSecretDraft(item)"
                      >
                        移除草稿
                      </button>
                      <button
                        v-else
                        class="ghost-button small"
                        type="button"
                        @click="toggleSecretRemoval(item)"
                      >
                        {{ item.remove ? '取消删除' : '标记删除' }}
                      </button>
                    </div>
                  </div>
                  <input
                    v-if="!item.remove"
                    v-model="item.next_value"
                    class="text-input settings-form-input"
                    type="password"
                    :placeholder="isDraftSecret(item) ? '可继续修改待保存的新值' : '留空表示保持当前值，填写后将更新'"
                  />
                </article>
              </div>
              <div v-else class="token-empty">当前没有保存任何隐藏敏感参数。</div>

              <div class="endpoint-secret-add">
                <input
                  v-model="form.new_secret_path"
                  class="text-input settings-form-input"
                  type="text"
                  placeholder="新增路径，例如 headers.Authorization"
                />
                <input
                  v-model="form.new_secret_value"
                  class="text-input settings-form-input"
                  type="password"
                  placeholder="新增敏感值"
                  @keydown.enter.prevent="addSecretDraft"
                />
                <button class="ghost-button small" type="button" @click="addSecretDraft">
                  加入隐藏项
                </button>
              </div>
            </div>
          </div>
        </details>
      </div>
    </section>

    <section class="ai-drawer-form-section">
      <div class="ai-drawer-form-header">
        <strong>保护策略</strong>
      </div>
      <div class="ai-drawer-form-list settings-form-list settings-form-list-compact">
        <div class="settings-form-row settings-form-row-compact">
          <div class="settings-form-copy">
            <h4>启用目标</h4>
          </div>
          <div class="settings-form-control">
            <label class="toggle-switch">
              <input v-model="form.enabled" class="toggle-input" type="checkbox" />
              <span class="toggle-ui" />
            </label>
          </div>
        </div>

        <div class="settings-form-row settings-form-row-compact">
          <div class="settings-form-copy">
            <h4>默认路由</h4>
          </div>
          <div class="settings-form-control">
            <label class="toggle-switch">
              <input v-model="form.is_default" class="toggle-input" type="checkbox" />
              <span class="toggle-ui" />
            </label>
          </div>
        </div>

        <div class="settings-form-row settings-form-row-compact">
          <div class="settings-form-copy">
            <h4>启用保护</h4>
          </div>
          <div class="settings-form-control">
            <label class="toggle-switch">
              <input v-model="form.protection_enabled" class="toggle-input" type="checkbox" />
              <span class="toggle-ui" />
            </label>
          </div>
        </div>

        <div class="settings-form-row settings-form-row-compact">
          <div class="settings-form-copy">
            <h4>保护模式</h4>
          </div>
          <div class="settings-form-control">
            <div class="mode-group">
              <button
                v-for="option in PROTECTION_MODE_OPTIONS"
                :key="option.value"
                :class="['ghost-button', 'small', { active: form.protection_mode === option.value }]"
                type="button"
                @click="form.protection_mode = option.value"
              >
                {{ option.label }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section v-if="testOutput" class="ai-drawer-form-section">
      <div class="ai-drawer-form-header">
        <strong>测试结果</strong>
      </div>
      <div class="control-result-panel">
        <div class="control-result-panel-copy">
          <h4>连通性结论</h4>
          <p class="control-result-panel-summary">{{ testOutput }}</p>
        </div>
        <div v-if="testUsage" class="token-list">
          <span v-for="[key, value] in Object.entries(testUsage)" :key="key" class="token-chip">
            {{ key }}: {{ String(value) }}
          </span>
        </div>
      </div>
    </section>

    <div class="ai-drawer-form-footer">
      <button
        v-if="mode === 'detail' && selectedEndpoint"
        class="ghost-button small"
        type="button"
        :disabled="busy"
        @click="$emit('test')"
      >
        测试
      </button>
      <button class="primary-button small" type="button" :disabled="busy" @click="$emit('save')">
        {{ mode === 'create' ? '创建目标' : '保存配置' }}
      </button>
      <button
        v-if="mode === 'detail' && selectedEndpoint"
        class="ghost-button small"
        type="button"
        :disabled="busy"
        @click="$emit('delete')"
      >
        删除
      </button>
    </div>
  </div>
</template>

<style scoped>
.endpoint-json-row {
  grid-template-columns: 1fr;
}

.endpoint-json-control {
  width: 100%;
  justify-content: stretch;
}

.endpoint-json-input {
  width: 100%;
  min-height: 180px;
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: white;
  color: var(--title);
  font: 12px/1.55 "Cascadia Code", "Consolas", monospace;
  resize: vertical;
}

.endpoint-json-input:focus {
  outline: 2px solid rgba(29, 99, 240, 0.15);
  border-color: #bfd1ef;
}

.endpoint-target-note {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 16px;
  border: 1px solid rgba(29, 99, 240, 0.12);
  border-radius: 12px;
  background: linear-gradient(135deg, rgba(244, 248, 255, 0.95), rgba(248, 250, 252, 0.98));
}

.endpoint-target-note-copy {
  display: grid;
  gap: 6px;
}

.endpoint-target-note-copy strong,
.endpoint-target-note-copy p {
  margin: 0;
}

.endpoint-advanced-card {
  border: 1px solid var(--line);
  border-radius: 12px;
  background: rgba(248, 250, 252, 0.72);
}

.endpoint-advanced-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 16px;
  cursor: pointer;
  list-style: none;
}

.endpoint-advanced-summary::-webkit-details-marker {
  display: none;
}

.endpoint-advanced-summary span {
  color: var(--text-secondary);
  font-size: 12px;
}

.endpoint-advanced-content {
  display: grid;
  gap: 14px;
  padding: 0 16px 16px;
}

.endpoint-inline-note {
  margin: 6px 0 0;
  color: var(--text-secondary);
  font-size: 12px;
}

.endpoint-secret-panel {
  display: grid;
  gap: 12px;
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: 10px;
  background: rgba(248, 250, 252, 0.9);
}

.endpoint-secret-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.endpoint-secret-head h4 {
  margin: 0;
}

.endpoint-secret-list {
  display: grid;
  gap: 10px;
}

.endpoint-secret-row {
  display: grid;
  gap: 8px;
  padding: 10px;
  border: 1px solid rgba(145, 163, 184, 0.22);
  border-radius: 10px;
  background: white;
}

.endpoint-secret-row.removed {
  border-color: rgba(214, 75, 70, 0.22);
  background: rgba(255, 241, 239, 0.7);
}

.endpoint-secret-row-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.endpoint-secret-row-copy {
  display: grid;
  gap: 4px;
}

.endpoint-secret-row-copy strong,
.endpoint-secret-row-copy p {
  margin: 0;
}

.endpoint-secret-row-copy p {
  color: var(--text-secondary);
  font-size: 12px;
}

.endpoint-secret-row-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.endpoint-secret-add {
  display: grid;
  gap: 10px;
  grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr) auto;
}

@media (max-width: 860px) {
  .endpoint-target-note,
  .endpoint-advanced-summary,
  .endpoint-secret-head,
  .endpoint-secret-row-head {
    flex-direction: column;
  }

  .endpoint-secret-add {
    grid-template-columns: 1fr;
  }
}
</style>
