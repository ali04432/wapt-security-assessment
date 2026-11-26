document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".score-progress[data-score]").forEach((element) => {
    const score = Number(element.dataset.score);
    if (Number.isFinite(score)) {
      element.style.width = `${Math.max(0, Math.min(100, score))}%`;
    }
  });
});
