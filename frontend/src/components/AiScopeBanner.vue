<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import StatusPill from './StatusPill.vue'
import { api, type AiEndpointItem } from '../services/api'

const props = withDefaults(
  defineProps<{
    endpointId?: number
    globalTitle?: string
    globalSummary?: string
  }>(),
  {
    globalTitle: '全局治理视图',
    globalSummary: '',
  }
)

const loading = ref(false)
const error = ref('')
const endpoint = ref<AiEndpointItem | null>(null)

const scoped = computed(() => Boolean(props.endpointId))
const heading = computed(() =>
  endpoint.value ? `当前目标：${endpoint.value.display_name}` : props.globalTitle
)

watch(
  () => props.endpointId,
  async (value) => {
    if (!value) {
      endpoint.value = null
      error.value = ''
      loading.value = false
      return
    }

    loading.value = true
    error.value = ''
    try {
      endpoint.value = await api.aiEndpoint(value)
    } catch (err) {
      endpoint.value = null
      error.value = err instanceof Error ? err.message : '无法加载当前目标'
    } finally {
      loading.value = false
    }
  },
  { immediate: true }
)
</script>

<template>
  <section :class="['ai-scope-banner', { scoped, loading, error: !endpoint && !!error }]">
    <div class="ai-scope-banner-copy">
      <p class="panel-kicker">{{ scoped ? '当前目标' : '全局视图' }}</p>
      <strong>{{ heading }}</strong>
    </div>

    <div class="ai-scope-banner-side">
      <template v-if="endpoint">
        <StatusPill :label="endpoint.protection_enabled ? '已纳入防护' : '仅路由目标'" :tone="endpoint.protection_enabled ? 'safe' : 'info'" />
        <StatusPill :label="endpoint.is_default ? '默认路由' : '专属目标'" :tone="endpoint.is_default ? 'warn' : 'info'" />
        <StatusPill :label="`Runtime ${endpoint.usage_summary.runtime_count}`" :tone="endpoint.usage_summary.runtime_online_count ? 'safe' : 'info'" />
        <StatusPill :label="`注册码 ${endpoint.usage_summary.token_count}`" tone="info" />
        <RouterLink class="ghost-button small" :to="{ name: 'ai-endpoints-detail', params: { endpointId: String(endpoint.id) } }">
          打开目标页
        </RouterLink>
      </template>
      <template v-else>
        <StatusPill :label="error ? '加载失败' : loading ? '加载中' : '共享策略'" :tone="error ? 'danger' : 'info'" />
        <RouterLink class="ghost-button small" :to="{ name: 'ai-endpoints' }">选择目标</RouterLink>
      </template>
    </div>
  </section>
</template>
