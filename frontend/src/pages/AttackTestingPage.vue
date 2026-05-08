<script setup lang="ts">
import SampleExecutionPage from './SampleExecutionPage.vue'
</script>

<template>
  <section class="attack-testing-shell">
    <header class="attack-testing-header">
      <div class="attack-testing-copy">
        <p class="attack-testing-kicker">攻击测试</p>
        <h1>独立攻击测试</h1>
        <p>单轮执行、批量回归、报告下载</p>
      </div>
      <div class="attack-testing-actions">
        <RouterLink class="ghost-button" to="/">返回防御平台</RouterLink>
      </div>
    </header>

    <SampleExecutionPage />
  </section>
</template>
