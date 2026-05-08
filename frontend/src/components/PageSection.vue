<script setup lang="ts">
import { ref, useSlots } from 'vue'
import StatusPill from './StatusPill.vue'

const props = withDefaults(
  defineProps<{
  eyebrow: string
  title: string
  tag?: string
  tone?: 'safe' | 'warn' | 'danger' | 'info'
  collapsible?: boolean
  defaultCollapsed?: boolean
}>(),
  {
    tone: 'info',
    collapsible: false,
    defaultCollapsed: false
  }
)

const slots = useSlots()
const collapsed = ref(Boolean(props.collapsible && props.defaultCollapsed))

function toggleCollapsed() {
  if (!props.collapsible) {
    return
  }
  collapsed.value = !collapsed.value
}
</script>

<template>
  <section :class="['panel', { 'panel-collapsed': collapsed }]">
    <div
      :class="[
        'panel-head',
        {
          'with-toolbar': slots.toolbar && !collapsed,
          'is-collapsible': props.collapsible,
          'panel-head-collapsed': collapsed,
        },
      ]"
    >
      <div class="panel-head-copy">
        <p class="panel-kicker">{{ props.eyebrow }}</p>
        <h3>{{ props.title }}</h3>
      </div>
      <div class="panel-head-side">
        <slot name="actions" />
        <StatusPill
          v-if="props.tag"
          :label="props.tag"
          :tone="props.tone"
        />
        <button
          v-if="props.collapsible"
          class="panel-collapse-button"
          :aria-expanded="!collapsed"
          type="button"
          @click="toggleCollapsed"
        >
          {{ collapsed ? '展开' : '收起' }}
        </button>
      </div>
    </div>
    <div v-if="!collapsed && slots.toolbar" class="panel-toolbar">
      <slot name="toolbar" />
    </div>
    <template v-if="!collapsed">
      <slot />
    </template>
  </section>
</template>
