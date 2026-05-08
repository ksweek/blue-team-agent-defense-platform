import { onMounted, ref } from 'vue'

export function useAsyncData<T>(loader: () => Promise<T>, immediate = true) {
  const data = ref<T | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)

  async function refresh() {
    loading.value = true
    error.value = null
    try {
      data.value = await loader()
    } catch (err) {
      error.value = err instanceof Error ? err.message : 'unknown error'
    } finally {
      loading.value = false
    }
  }

  if (immediate) {
    onMounted(() => {
      void refresh()
    })
  }

  return {
    data,
    loading,
    error,
    refresh
  }
}
