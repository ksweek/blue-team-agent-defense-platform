<script setup lang="ts">
defineProps<{
  label: string
  tone?: 'safe' | 'warn' | 'danger' | 'info'
}>()
</script>

<template>
  <span :class="['status-pill', `tone-${tone ?? 'info'}`]">{{ label }}</span>
</template>
