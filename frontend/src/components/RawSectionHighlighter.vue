<script setup lang="ts">
import { computed } from 'vue'
import StatusPill from './StatusPill.vue'
import type { RawHighlightRow } from '../services/rawHighlight'

const props = defineProps<{
  rows: RawHighlightRow[]
  showHitsOnly: boolean
  activeLocationKey?: string | null
}>()

const visibleRows = computed(() =>
  props.showHitsOnly ? props.rows.filter((row) => row.hasHits) : props.rows
)
</script>

<template>
  <div v-if="visibleRows.length" class="security-raw-row-list">
    <article
      v-for="row in visibleRows"
      :key="row.anchor"
      :class="['security-raw-row', { active: activeLocationKey === row.locationKey }]"
      :data-raw-location-key="row.locationKey"
      :data-raw-row-anchor="row.anchor"
    >
      <div class="security-raw-row-head">
        <span class="security-raw-path">{{ row.label }}</span>
        <div class="security-raw-row-tags">
          <StatusPill
            v-if="row.payloadPatterns.length"
            :label="`Payload ${row.payloadPatterns.length}`"
            tone="warn"
          />
          <StatusPill
            v-if="row.sensitiveLabels.length"
            :label="`敏感 ${row.sensitiveLabels.length}`"
            tone="danger"
          />
        </div>
      </div>

      <div v-if="row.payloadPatterns.length || row.sensitiveLabels.length" class="security-raw-tags">
        <span
          v-for="item in row.payloadPatterns"
          :key="`payload-${row.anchor}-${item}`"
          class="token-chip token-chip-warn"
        >
          <span>{{ item }}</span>
        </span>
        <span
          v-for="item in row.sensitiveLabels"
          :key="`sensitive-${row.anchor}-${item}`"
          class="token-chip token-chip-danger"
        >
          <span>{{ item }}</span>
        </span>
      </div>

      <pre class="security-raw-value"><template v-for="(segment, index) in row.segments" :key="`${row.anchor}-${index}-${segment.kind}`"><span :class="['security-raw-segment', `security-raw-segment-${segment.kind}`]" :title="segment.label">{{ segment.text }}</span></template></pre>
    </article>
  </div>
  <div v-else class="token-empty">当前筛选下没有命中行。</div>
</template>
