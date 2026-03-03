// KHARMA SENTINEL - Tour Manager

const TourManager = {
    currentStep: 0,
    steps: [
        { target: '.stats-grid', key: 'tour_1' },
        { target: '.map-section', key: 'tour_2' },
        { target: '.dashboard-container', key: 'tour_3' },
        { target: '.dpi-section', key: 'tour_4' },
        { target: '.brand', key: 'tour_5' }
    ],

    start: function () {
        this.currentStep = 0;
        const overlay = document.getElementById('onboarding-overlay');
        if (overlay) overlay.classList.remove('active');
        this.showStep();
    },

    showStep: function () {
        const step = this.steps[this.currentStep];
        const el = document.querySelector(step.target);
        const tooltip = document.getElementById('sentinel-tooltip');
        const t = translations[currentLang];

        document.querySelectorAll('.tour-highlight').forEach(h => h.classList.remove('tour-highlight'));

        if (el) {
            el.classList.add('tour-highlight');
            this.positionTooltip(el, tooltip);
        }

        const titleEl = document.getElementById('tooltip-title');
        const contentEl = document.getElementById('tooltip-content');
        if (titleEl) titleEl.innerText = t[step.key + '_title'];
        if (contentEl) contentEl.innerText = t[step.key + '_text'];

        const prevBtn = document.getElementById('tour-prev');
        const nextBtn = document.getElementById('tour-next');
        if (prevBtn) {
            prevBtn.innerText = t.tour_prev;
            prevBtn.style.display = this.currentStep === 0 ? 'none' : 'block';
        }
        if (nextBtn) {
            nextBtn.innerText = this.currentStep === (this.steps.length - 1) ? t.tour_finish : t.tour_next;
        }

        this.renderDots();
        if (tooltip) tooltip.classList.add('active');
        if (typeof lucide !== 'undefined') lucide.createIcons();
    },

    positionTooltip: function (targetEl, tooltip) {
        if (!targetEl || !tooltip) return;
        const rect = targetEl.getBoundingClientRect();
        const arrow = document.getElementById('tooltip-arrow');

        let top = rect.bottom + 20;
        let left = rect.left + (rect.width / 2) - 160;

        if (left < 20) left = 20;
        if (left + 320 > window.innerWidth) left = window.innerWidth - 340;

        if (top + 200 > window.innerHeight) {
            top = rect.top - 200;
            if (arrow) {
                arrow.style.top = 'auto';
                arrow.style.bottom = '-6px';
                arrow.style.borderLeft = 'none';
                arrow.style.borderTop = 'none';
                arrow.style.borderRight = '1px solid var(--accent)';
                arrow.style.borderBottom = '1px solid var(--accent)';
            }
        } else if (arrow) {
            arrow.style.top = '-6px';
            arrow.style.bottom = 'auto';
            arrow.style.borderRight = 'none';
            arrow.style.borderBottom = 'none';
            arrow.style.borderLeft = '1px solid var(--accent)';
            arrow.style.borderTop = '1px solid var(--accent)';
        }

        tooltip.style.top = top + 'px';
        tooltip.style.left = left + 'px';
        if (arrow) arrow.style.left = (rect.left + (rect.width / 2) - left - 6) + 'px';
    },

    renderDots: function () {
        const container = document.getElementById('tour-dots');
        if (container) {
            container.innerHTML = this.steps.map((_, i) => `<div class="tour-dot ${i === this.currentStep ? 'active' : ''}"></div>`).join('');
        }
    },

    next: function () {
        if (this.currentStep < this.steps.length - 1) {
            this.currentStep++;
            this.showStep();
        } else {
            this.finish();
        }
    },

    prev: function () {
        if (this.currentStep > 0) {
            this.currentStep--;
            this.showStep();
        }
    },

    finish: function () {
        const tooltip = document.getElementById('sentinel-tooltip');
        if (tooltip) tooltip.classList.remove('active');
        document.querySelectorAll('.tour-highlight').forEach(h => h.classList.remove('tour-highlight'));
        localStorage.setItem('kharma_onboarded', 'true');
    }
};

function startTour() {
    TourManager.start();
}
