<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  name: 'dashboard' | 'samples' | 'ai' | 'config' | 'events' | 'assets' | 'skills' | 'settings'
}>()

const iconPath = computed(() => props.name)
</script>

<template>
  <svg
    class="sidebar-icon-svg"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-linecap="round"
    stroke-linejoin="round"
    stroke-width="1.8"
    aria-hidden="true"
  >
    <template v-if="iconPath === 'dashboard'">
      <path d="M4 13.5h6.5V20H4z" />
      <path d="M13.5 4H20v7.5h-6.5z" />
      <path d="M13.5 13.5H20V20h-6.5z" />
      <path d="M4 4h6.5v6.5H4z" />
    </template>

    <template v-else-if="iconPath === 'samples'">
      <path d="M6 4.5h8l4 4V19.5H6z" />
      <path d="M14 4.5v4h4" />
      <path d="M8.5 12h7" />
      <path d="M8.5 15.5h5.5" />
    </template>

    <template v-else-if="iconPath === 'ai'">
      <path d="M6 6.5h12v11H6z" />
      <path d="M9 3.5v3" />
      <path d="M15 3.5v3" />
      <path d="M9 17.5v3" />
      <path d="M15 17.5v3" />
      <path d="M3.5 9h3" />
      <path d="M17.5 9h3" />
      <path d="M3.5 15h3" />
      <path d="M17.5 15h3" />
      <path d="M9.5 10.5h5" />
      <path d="M10 14h4" />
    </template>

    <template v-else-if="iconPath === 'config'">
      <path d="M12 3.5v3" />
      <path d="M12 17.5v3" />
      <path d="M4.8 7.8l2.1 2.1" />
      <path d="M17.1 15.1l2.1 2.1" />
      <path d="M3.5 12h3" />
      <path d="M17.5 12h3" />
      <path d="M4.8 16.2l2.1-2.1" />
      <path d="M17.1 8.9l2.1-2.1" />
      <circle cx="12" cy="12" r="3.2" />
    </template>

    <template v-else-if="iconPath === 'events'">
      <path d="M7 5.5h10" />
      <path d="M7 10.5h10" />
      <path d="M7 15.5h6" />
      <path d="M5 5.5h.01" />
      <path d="M5 10.5h.01" />
      <path d="M5 15.5h.01" />
      <path d="M15.5 18.5l1.8 1.8 3.2-3.8" />
    </template>

    <template v-else-if="iconPath === 'assets'">
      <path d="M12 3.8 5.5 6.2v5.7c0 4 2.6 6.8 6.5 8.3 3.9-1.5 6.5-4.3 6.5-8.3V6.2z" />
      <path d="m9.7 12.1 1.6 1.7 3-3.3" />
    </template>

    <template v-else-if="iconPath === 'skills'">
      <path d="M14.5 4.5a3.5 3.5 0 1 1-4.6 5.1L5 14.5V19h4.5l4.9-4.9a3.5 3.5 0 0 0 5.1-4.6l-2.3 2.3-2.8-2.8z" />
    </template>

    <template v-else>
      <path d="M4.5 8.2 12 4l7.5 4.2v7.6L12 20l-7.5-4.2z" />
      <path d="M12 9.2v3.3" />
      <path d="M12 15.8h.01" />
    </template>
  </svg>
</template>
