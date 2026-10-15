"use client";

export default function SkipToMain() {
  function focusMain() {
    const main = document.querySelector<HTMLElement>("main");
    if (!main) return;
    main.tabIndex = -1;
    main.focus({ preventScroll: true });
    main.scrollIntoView({ block: "start" });
  }

  return (
    <button
      type="button"
      onClick={focusMain}
      className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:rounded-md focus:bg-[#253044] focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-white focus:outline-2 focus:outline-offset-2 focus:outline-[#5856d6]"
    >
      Skip to main content
    </button>
  );
}
