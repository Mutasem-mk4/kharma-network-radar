// KHARMA SENTINEL - Charting Module (Chart.js)

var chartData = {
    labels: [],
    datasets: [
        { label: 'Down', borderColor: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.1)', data: [], fill: true, tension: 0.4 },
        { label: 'Up', borderColor: '#10b981', backgroundColor: 'rgba(16, 185, 129, 0.1)', data: [], fill: true, tension: 0.4 }
    ]
};

let _lastChartTime = 0;

function initChart() {
    const ctx = document.getElementById('bw-chart')?.getContext('2d');
    if (!ctx) return;

    bwChart = new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { display: false },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: 'rgba(255,255,255,0.5)', font: { size: 10 } }
                }
            }
        }
    });
}

function updateChart(tin, tout) {
    if (!bwChart) return;
    const nowMs = Date.now();
    if (nowMs - _lastChartTime < 1000) return;
    _lastChartTime = nowMs;

    const timeStr = new Date().toLocaleTimeString();
    chartData.labels.push(timeStr);
    chartData.datasets[0].data.push(tin);
    chartData.datasets[1].data.push(tout);

    if (chartData.labels.length > 20) {
        chartData.labels.shift();
        chartData.datasets[0].data.shift();
        chartData.datasets[1].data.shift();
    }
    bwChart.update('none');
}
