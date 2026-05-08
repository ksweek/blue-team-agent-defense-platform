import { nextTick, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'

type FocusHook = (focus: string, route: ReturnType<typeof useRoute>) => void | Promise<void>

function getQueryValue(value: unknown) {
  return typeof value === 'string' && value.trim() ? value : null
}

export function useRouteSectionFocus(beforeScroll?: FocusHook) {
  const route = useRoute()

  async function focusSection() {
    const focus = getQueryValue(route.query.focus)
    if (!focus) {
      return
    }

    await beforeScroll?.(focus, route)
    await nextTick()

    const target =
      document.getElementById(focus) ??
      document.querySelector<HTMLElement>(`[data-page-anchor="${focus}"]`)

    if (!target) {
      return
    }

    target.scrollIntoView({
      behavior: 'smooth',
      block: 'start',
    })
  }

  onMounted(() => {
    void focusSection()
  })

  watch(
    () => route.fullPath,
    () => {
      void focusSection()
    }
  )
}
