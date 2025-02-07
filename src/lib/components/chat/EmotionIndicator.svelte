<script>
  export let emotion = 'neutru';

  const emotionLabels = {
    'tristețe': '😢 Tristețe',
    'frică': '😨 Frică',
    'furie': '😠 Furie',
    'rușine': '😳 Rușine',
    'neutru': '😐 Neutru',
    'anxietate': '😰 Anxietate',
    'bucurie': '😊 Bucurie',
    'speranță': '🤗 Speranță'
  };

  const emotionIcons = {
    'tristețe': '😢',
    'frică': '😨',
    'furie': '😠',
    'rușine': '😳',
    'neutru': '😐',
    'anxietate': '😰',
    'bucurie': '😊',
    'speranță': '🤗'
  };

  let isTooltipVisible = false;
</script>

<div
  class="inline-flex items-center relative"
  on:mouseenter={() => isTooltipVisible = true}
  on:mouseleave={() => isTooltipVisible = false}
  on:focusin={() => isTooltipVisible = true}
  on:focusout={() => isTooltipVisible = false}
>
  <span class="text-xl cursor-pointer">
    {emotionIcons[emotion] || emotionIcons['neutru']}
  </span>

  {#if isTooltipVisible}
    <div class="absolute bottom-full mb-2 z-50">
      <div class="bg-gray-900 text-white text-sm rounded py-1 px-2 whitespace-nowrap">
        {emotionLabels[emotion] || emotion}
      </div>
    </div>
  {/if}
</div>

<style>
  div {
    transition: opacity 0.2s ease-in-out;
  }
</style>