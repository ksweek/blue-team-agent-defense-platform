<script setup lang="ts">
import StatusPill from './StatusPill.vue'

type Tone = 'safe' | 'warn' | 'danger' | 'info'

type StatusRailItem = {
  label: string
  value: string
  tone: Tone
  tag?: string
  meta?: string
  trend?: string
  detail?: string
}

defineProps<{
  title: string
  summary: string
  items: StatusRailItem[]
  statusLabel?: string
  statusTone?: Tone
  meta?: string
}>()
</script>

<template>
  <section class="status-rail">
    <article :class="['status-rail-main', `tone-${statusTone ?? 'info'}`]">
      <div class="status-rail-main-copy">
        <span class="status-rail-title">{{ title }}</span>
        <strong class="status-rail-summary">{{ summary }}</strong>
        <p v-if="meta" class="status-rail-meta">{{ meta }}</p>
      </div>

      <div class="status-rail-main-side">
        <StatusPill v-if="statusLabel" :label="statusLabel" :tone="statusTone ?? 'info'" />
        <slot name="actions" />
      </div>
    </article>

    <div class="status-rail-items">
      <article
        v-for="item in items"
        :key="item.label"
        :class="['status-rail-item', `tone-${item.tone}`]"
      >
        <div class="status-rail-item-head">
          <span class="status-rail-item-label">{{ item.label }}</span>
          <StatusPill v-if="item.tag" :label="item.tag" :tone="item.tone" />
        </div>
        <strong class="status-rail-item-value">{{ item.value }}</strong>
        <span v-if="item.meta || item.trend || item.detail" class="status-rail-item-meta">
          {{ item.meta || item.trend || item.detail }}
        </span>
      </article>
    </div>
  </section>
</template>
