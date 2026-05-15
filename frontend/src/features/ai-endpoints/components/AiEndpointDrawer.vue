<script setup lang="ts">
import { computed } from 'vue'
import type { AiEndpointItem } from '../../../services/api'
import StatusPill from '../../../components/StatusPill.vue'
import { PROTECTION_MODE_OPTIONS, PROVIDER_OPTIONS } from '../constants'
import { endpointStatusLabel, endpointTone } from '../helpers'
import type { EndpointForm, EndpointSecretDraft } from '../useAiEndpointsPage'

const props = defineProps<{
  open: boolean
  mode: 'create' | 'detail'
  title: string
  summary: string
  busy: boolean
  form: EndpointForm
  selectedEndpoint: AiEndpointItem | null
  testOutput: string
  testUsage: Record<string, unknown> | null
}>()

defineEmits<{
  close: []
  save: []
  test: []
  delete: []
}>()

const secretSummaryText = computed(() => {
  if (props.mode === 'detail' && props.selectedEndpoint?.config_secret_summary) {
    return props.selectedEndpoint.config_secret_summary
  }
  if (props.form.config_secret_items.length) {
    return `已配置 ${props.form.config_secret_items.length} 项隐藏敏感参数`
  }
  return '当前没有隐藏敏感参数'
})

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
  if (item.value_type === 'number') return '数值'
  if (item.value_type === 'boolean') return '布尔'
  if (item.value_type === 'null') return '空值'
  return '字符串'
}
</script>

<template>
  <Teleport to="body">
    <Transition name="ai-drawer-fade">
      <div v-if="open" class="ai-drawer-shell">
        <button class="ai-drawer-backdrop" type="button" aria-label="关闭" @click="$emit('close')" />
        <Transition name="ai-drawer-slide">
          <aside v-if="open" class="ai-drawer-overlay">
            <section class="ai-drawer-panel">
              <div class="ai-drawer-panel-head">
                <div class="ai-drawer-panel-copy">
                  <div class="ai-drawer-panel-titleline">
                    <p class="panel-kicker">{{ mode === 'create' ? '新增' : '配置' }}</p>
                    <h4>{{ title }}</h4>
                  </div>
                  <p class="ai-drawer-panel-summary">{{ summary }}</p>
                </div>

                <div class="ai-drawer-panel-side">
                  <StatusPill
                    v-if="mode === 'detail' && selectedEndpoint"
                    :label="endpointStatusLabel(selectedEndpoint)"
                    :tone="endpointTone(selectedEndpoint)"
                  />
                  <button class="ghost-button small endpoint-icon-button" type="button" @click="$emit('close')">
                    ×
                  </button>
                </div>
              </div>

              <div class="ai-drawer-panel-body">
                <div class="ai-drawer-form-stack">
                  <section class="ai-drawer-form-section">
                    <div class="ai-drawer-form-header">
                      <strong>基础标识</strong>
                      <span>接入名称、分组与说明</span>
                    </div>
                    <div class="ai-drawer-form-list settings-form-list settings-form-list-compact">
                      <div class="settings-form-row settings-form-row-compact">
                        <div class="settings-form-copy">
                          <h4>端点标识</h4>
                          <p class="card-subtitle">建议使用英文和短横线</p>
                        </div>
                        <div class="settings-form-control">
                          <input v-model="form.endpoint_key" class="text-input settings-form-input" type="text" placeholder="openai-prod-cn" />
                        </div>
                      </div>

                      <div class="settings-form-row settings-form-row-compact">
                        <div class="settings-form-copy">
                          <h4>显示名称</h4>
                          <p class="card-subtitle">页面展示与默认路由使用</p>
                        </div>
                        <div class="settings-form-control">
                          <input v-model="form.display_name" class="text-input settings-form-input" type="text" placeholder="生产网关" />
                        </div>
                      </div>

                      <div class="settings-form-row settings-form-row-compact">
                        <div class="settings-form-copy">
                          <h4>分组</h4>
                          <p class="card-subtitle">按业务线或环境归类</p>
                        </div>
                        <div class="settings-form-control">
                          <input v-model="form.endpoint_group" class="text-input settings-form-input" type="text" placeholder="production" />
                        </div>
                      </div>

                      <div class="settings-form-row settings-form-row-compact">
                        <div class="settings-form-copy">
                          <h4>说明</h4>
                          <p class="card-subtitle">可留空</p>
                        </div>
                        <div class="settings-form-control">
                          <input v-model="form.description" class="text-input settings-form-input" type="text" placeholder="用于在线防护代理入口" />
                        </div>
                      </div>
                    </div>
                  </section>

                  <section class="ai-drawer-form-section">
                    <div class="ai-drawer-form-header">
                      <strong>接入配置</strong>
                      <span>模型端点、认证与安全配置</span>
                    </div>
                    <div class="ai-drawer-form-list settings-form-list settings-form-list-compact">
                      <div class="settings-form-row settings-form-row-compact">
                        <div class="settings-form-copy">
                          <h4>协议类型</h4>
                          <p class="card-subtitle">选择接入协议</p>
                        </div>
                        <div class="settings-form-control">
                          <select v-model="form.provider_type" class="select-input settings-form-select">
                            <option v-for="option in PROVIDER_OPTIONS" :key="option.value" :value="option.value">
                              {{ option.label }}
                            </option>
                          </select>
                        </div>
                      </div>

                      <div class="settings-form-row settings-form-row-compact">
                        <div class="settings-form-copy">
                          <h4>接入地址</h4>
                          <p class="card-subtitle">例如 OpenAI / vLLM / one-api 网关</p>
                        </div>
                        <div class="settings-form-control">
                          <input v-model="form.base_url" class="text-input settings-form-input" type="text" placeholder="https://api.example.com/v1" />
                        </div>
                      </div>

                      <div class="settings-form-row settings-form-row-compact">
                        <div class="settings-form-copy">
                          <h4>模型名称</h4>
                          <p class="card-subtitle">请求时使用的 model 字段</p>
                        </div>
                        <div class="settings-form-control">
                          <input v-model="form.model_name" class="text-input settings-form-input" type="text" placeholder="gpt-4.1-mini" />
                        </div>
                      </div>

                      <div class="settings-form-row settings-form-row-compact">
                        <div class="settings-form-copy">
                          <h4>API Key</h4>
                          <p class="card-subtitle">
                            {{
                              mode === 'detail' && selectedEndpoint?.has_api_key
                                ? `已保存: ${selectedEndpoint.api_key_hint}`
                                : '首次接入请填写认证密钥'
                            }}
                          </p>
                        </div>
                        <div class="settings-form-control">
                          <input
                            v-model="form.api_key"
                            class="text-input settings-form-input"
                            type="password"
                            :placeholder="mode === 'detail' ? '留空表示不更新现有密钥' : 'sk-...'"
                          />
                        </div>
                      </div>

                      <div class="settings-form-row settings-form-row-compact settings-form-row-nested endpoint-json-row">
                        <div class="settings-form-copy">
                          <h4>公开配置 JSON</h4>
                          <p class="card-subtitle">只填写可公开回显的参数，例如超时、非敏感 headers、extra_body</p>
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
                            <p class="card-subtitle">{{ secretSummaryText }}</p>
                          </div>
                          <StatusPill :label="`${form.config_secret_items.length} 项`" :tone="form.config_secret_items.length ? 'warn' : 'info'" />
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
                                <p>{{ isDraftSecret(item) ? '新增敏感项，保存后将只显示掩码。' : `当前值 ${item.masked_value}` }}</p>
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
                              :placeholder="isDraftSecret(item) ? '新增值已写入草稿，可继续修改' : '留空表示保持当前值，填写后将更新'"
                            />
                          </article>
                        </div>
                        <div v-else class="token-empty">当前没有已保存的隐藏敏感参数。</div>

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
                  </section>

                  <section class="ai-drawer-form-section">
                    <div class="ai-drawer-form-header">
                      <strong>防护策略</strong>
                      <span>接入启停、默认路由与执行前防护</span>
                    </div>
                    <div class="ai-drawer-form-list settings-form-list settings-form-list-compact">
                      <div class="settings-form-row settings-form-row-compact">
                        <div class="settings-form-copy">
                          <h4>启用接入</h4>
                          <p class="card-subtitle">关闭后不参与路由</p>
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
                          <p class="card-subtitle">未指定端点时回退到这里</p>
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
                          <h4>启用防护</h4>
                          <p class="card-subtitle">执行前策略评估</p>
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
                          <h4>防护模式</h4>
                          <p class="card-subtitle">命中后如何处理请求</p>
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
                      <span>连通性与返回摘要</span>
                    </div>
                    <div class="control-result-panel">
                      <div class="control-result-panel-copy">
                        <h4>模型响应</h4>
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
                      {{ mode === 'create' ? '新增并纳管' : '保存配置' }}
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
              </div>
            </section>
          </aside>
        </Transition>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.endpoint-icon-button {
  min-width: 28px;
  width: 28px;
  height: 28px;
  padding: 0;
  font-size: 1rem;
  line-height: 1;
}

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
  gap: 10px;
  padding: 10px 12px;
  border: 1px solid rgba(204, 214, 229, 0.9);
  border-radius: 10px;
  background: white;
}

.endpoint-secret-row.removed {
  background: rgba(255, 245, 245, 0.95);
  border-color: rgba(225, 76, 76, 0.22);
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

.endpoint-secret-row-copy strong {
  font-size: 12px;
  color: var(--title);
}

.endpoint-secret-row-copy p {
  margin: 0;
  font-size: 12px;
  color: var(--muted);
}

.endpoint-secret-row-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.endpoint-secret-add {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr) auto;
  gap: 10px;
}

@media (max-width: 960px) {
  .endpoint-secret-row-head {
    flex-direction: column;
  }

  .endpoint-secret-row-meta {
    justify-content: flex-start;
  }

  .endpoint-secret-add {
    grid-template-columns: 1fr;
  }
}
</style>
