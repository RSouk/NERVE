/**
 * GHOST Security Roadmap - JavaScript Module
 * Handles all roadmap functionality including:
 * - Profile management
 * - Task loading, filtering, and status updates
 * - Progress tracking and visualization
 * - Achievement system
 * - Score animations
 */

const API_URL = 'http://localhost:5000';

// State management
let currentProfile = null;
let currentTasks = [];
let currentStats = {};
let activePhase = null;
let activeFilter = 'all';
let progressChart = null;
let currentTaskId = null;

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', initRoadmap);

async function initRoadmap() {
    console.log('[Roadmap] Initializing...');
    showLoading(true);

    try {
        await loadProfile();
    } catch (error) {
        console.error('[Roadmap] Initialization error:', error);
        showEmptyState();
    }
}

// ============================================================================
// PROFILE MANAGEMENT
// ============================================================================

async function loadProfile() {
    try {
        const response = await fetch(`${API_URL}/api/roadmap/profile`);
        const data = await response.json();

        if (!data.profile) {
            showEmptyState();
            return null;
        }

        currentProfile = data.profile;
        await loadDashboard();
        return currentProfile;
    } catch (error) {
        console.error('[Roadmap] Error loading profile:', error);
        showEmptyState();
        return null;
    }
}

async function saveProfile(profileData) {
    try {
        const response = await fetch(`${API_URL}/api/roadmap/profile`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(profileData)
        });

        if (!response.ok) throw new Error('Failed to save profile');

        const data = await response.json();
        currentProfile = data.profile;
        return data;
    } catch (error) {
        console.error('[Roadmap] Error saving profile:', error);
        throw error;
    }
}

// ============================================================================
// DASHBOARD LOADING
// ============================================================================

async function loadDashboard() {
    showLoading(true);

    try {
        // Load all data in parallel
        const [statsRes, tasksRes, progressRes, achievementsRes] = await Promise.all([
            fetch(`${API_URL}/api/roadmap/stats`),
            fetch(`${API_URL}/api/roadmap/tasks`),
            fetch(`${API_URL}/api/roadmap/progress`),
            fetch(`${API_URL}/api/roadmap/achievements`)
        ]);

        const stats = await statsRes.json();
        const tasks = await tasksRes.json();
        const progress = await progressRes.json();
        const achievements = await achievementsRes.json();

        currentStats = stats;
        currentTasks = tasks.tasks || [];

        // Show main content
        document.getElementById('emptyState').style.display = 'none';
        document.getElementById('roadmapContent').style.display = 'block';

        // Render all sections
        renderScoreGauge(stats);
        renderQuickStats(stats);
        renderScanBanner(stats);
        renderTasks(currentTasks);
        renderAchievements(achievements);
        renderProgressChart(progress);
        updatePhaseProgress(currentTasks);

        showLoading(false);

    } catch (error) {
        console.error('[Roadmap] Error loading dashboard:', error);
        showLoading(false);
    }
}

// ============================================================================
// TASK MANAGEMENT
// ============================================================================

async function loadTasks() {
    try {
        const response = await fetch(`${API_URL}/api/roadmap/tasks`);
        const data = await response.json();
        currentTasks = data.tasks || [];
        return currentTasks;
    } catch (error) {
        console.error('[Roadmap] Error loading tasks:', error);
        return [];
    }
}

function renderTasks(tasks) {
    const containers = {
        1: document.getElementById('phase1Tasks'),
        2: document.getElementById('phase2Tasks'),
        3: document.getElementById('phase3Tasks'),
        4: document.getElementById('phase4Tasks')
    };

    // Clear all containers
    Object.values(containers).forEach(c => { if (c) c.innerHTML = ''; });

    // Apply filters
    let filteredTasks = tasks;
    if (activeFilter !== 'all') {
        if (activeFilter === 'scan') {
            filteredTasks = tasks.filter(t => t.source && t.source.includes('scan'));
        } else {
            filteredTasks = tasks.filter(t => t.status === activeFilter);
        }
    }

    // Group by phase
    const grouped = { 1: [], 2: [], 3: [], 4: [] };
    filteredTasks.forEach(task => {
        const phase = task.phase || 4;
        if (grouped[phase]) {
            grouped[phase].push(task);
        }
    });

    // Render each phase
    Object.entries(grouped).forEach(([phase, phaseTasks]) => {
        const container = containers[phase];
        if (!container) return;

        if (phaseTasks.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 20px; color: var(--text-muted); font-size: 0.9rem;">
                    No tasks in this phase
                </div>
            `;
            return;
        }

        container.innerHTML = phaseTasks.map(task => createTaskCard(task)).join('');
    });
}

function createTaskCard(task) {
    const isFromScan = task.source && task.source.includes('scan');
    const statusIcon = getStatusIcon(task.status);

    return `
        <div class="task-card ${task.status} ${isFromScan ? 'from-scan' : ''}"
             data-task-id="${task.id}"
             onclick="openTaskModal(${task.id})">
            <div class="task-status ${task.status}">${statusIcon}</div>
            <div class="task-content">
                <div class="task-title">${escapeHtml(task.task_name)}</div>
                <div class="task-description">${escapeHtml(task.description || '')}</div>
                <div class="task-meta">
                    <span class="task-meta-item impact">+${task.security_score_impact || 5} pts</span>
                    <span class="task-meta-item time">${task.estimated_time_minutes || 30} min</span>
                    ${task.estimated_cost ? `<span class="task-meta-item cost">${task.estimated_cost}</span>` : ''}
                </div>
            </div>
            <div class="task-actions" onclick="event.stopPropagation()">
                <button class="task-btn secondary" onclick="openTaskModal(${task.id})">How to Fix</button>
                ${task.status !== 'completed' ? `
                    <button class="task-btn primary" onclick="markTaskComplete(${task.id})">I Fixed This</button>
                    ${isFromScan ? `<button class="task-btn verify" onclick="verifyTaskFix(${task.id})">Verify</button>` : ''}
                ` : ''}
            </div>
        </div>
    `;
}

function getStatusIcon(status) {
    switch (status) {
        case 'completed': return '&#10003;';
        case 'in_progress': return '&#8635;';
        default: return '&bull;';
    }
}

function filterTasks(filter) {
    activeFilter = filter;

    // Update button states
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.filter === filter) {
            btn.classList.add('active');
        }
    });

    renderTasks(currentTasks);
}

// ============================================================================
// PHASE ACCORDION
// ============================================================================

function togglePhase(phaseNum) {
    const section = document.querySelector(`.phase-section[data-phase="${phaseNum}"]`);
    if (section) {
        section.classList.toggle('expanded');
    }
}

function updatePhaseProgress(tasks) {
    const phases = [1, 2, 3, 4];

    phases.forEach(phase => {
        const phaseTasks = tasks.filter(t => t.phase === phase);
        const completed = phaseTasks.filter(t => t.status === 'completed').length;
        const total = phaseTasks.length;
        const percent = total > 0 ? Math.round((completed / total) * 100) : 0;

        const progressEl = document.getElementById(`phase${phase}Progress`);
        const fillEl = document.getElementById(`phase${phase}Fill`);

        if (progressEl) progressEl.textContent = `${completed}/${total}`;
        if (fillEl) fillEl.style.width = `${percent}%`;
    });
}

// ============================================================================
// TASK STATUS UPDATES
// ============================================================================

async function markTaskComplete(taskId) {
    try {
        const response = await fetch(`${API_URL}/api/roadmap/task/${taskId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: 'completed' })
        });

        const data = await response.json();

        if (data.success) {
            // Get task info for animation
            const task = currentTasks.find(t => t.id === taskId);
            const points = task ? (task.security_score_impact || 5) : 5;

            // Animate score increase
            animateScoreIncrease(points);

            // Check for achievements
            if (data.achievements_unlocked && data.achievements_unlocked.length > 0) {
                data.achievements_unlocked.forEach(ach => {
                    setTimeout(() => showAchievementUnlock(ach), 1500);
                });
            }

            // Reload dashboard
            await loadDashboard();

            // Close modal if open
            closeTaskModal();
        }
    } catch (error) {
        console.error('[Roadmap] Error completing task:', error);
    }
}

async function verifyTaskFix(taskId) {
    showLoading(true, 'Verifying fix...');

    try {
        const response = await fetch(`${API_URL}/api/roadmap/task/${taskId}/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.verified) {
            showNotification('success', 'Fix verified! Task marked as complete.');
            await markTaskComplete(taskId);
        } else {
            showNotification('warning', 'Issue still detected. Please review your fix.');
        }
    } catch (error) {
        console.error('[Roadmap] Error verifying task:', error);
        showNotification('error', 'Verification failed. Please try again.');
    } finally {
        showLoading(false);
    }
}

// ============================================================================
// TASK MODAL
// ============================================================================

function openTaskModal(taskId) {
    const task = currentTasks.find(t => t.id === taskId);
    if (!task) return;

    currentTaskId = taskId;

    document.getElementById('modalTitle').textContent = task.task_name;
    document.getElementById('modalDescription').textContent = task.description || 'No description available.';
    document.getElementById('modalWhy').textContent = task.why_it_matters || 'This helps improve your overall security posture.';

    // Parse how to fix steps
    const stepsContainer = document.getElementById('modalSteps');
    const howToFix = task.how_to_fix || 'Contact your IT administrator for guidance.';
    const steps = howToFix.split(/\d+\.\s*/).filter(s => s.trim());

    if (steps.length > 0) {
        stepsContainer.innerHTML = steps.map(step => `<li>${escapeHtml(step.trim())}</li>`).join('');
    } else {
        stepsContainer.innerHTML = `<li>${escapeHtml(howToFix)}</li>`;
    }

    // Resources
    const resourcesEl = document.getElementById('modalResources');
    if (task.external_resources) {
        try {
            const resources = JSON.parse(task.external_resources);
            resourcesEl.innerHTML = resources.map(r =>
                `<a href="${escapeHtml(r.url)}" target="_blank" style="color: var(--accent-cyan); display: block; margin-bottom: 8px;">${escapeHtml(r.title)}</a>`
            ).join('');
        } catch {
            resourcesEl.textContent = task.external_resources;
        }
    } else {
        resourcesEl.textContent = 'No additional resources available.';
    }

    // Update complete button state
    const completeBtn = document.getElementById('modalCompleteBtn');
    if (task.status === 'completed') {
        completeBtn.textContent = 'Already Completed';
        completeBtn.disabled = true;
    } else {
        completeBtn.textContent = 'Mark as Fixed';
        completeBtn.disabled = false;
    }

    document.getElementById('taskModal').classList.add('active');
}

function closeTaskModal() {
    document.getElementById('taskModal').classList.remove('active');
    currentTaskId = null;
}

function markCurrentTaskComplete() {
    if (currentTaskId) {
        markTaskComplete(currentTaskId);
    }
}

// ============================================================================
// SCORE VISUALIZATION
// ============================================================================

function renderScoreGauge(stats) {
    const score = stats.security_score || 0;
    const target = stats.target_score || 85;

    // Animate score value
    const scoreEl = document.getElementById('scoreValue');
    if (scoreEl) {
        animateNumber(scoreEl, 0, score, 1500);
    }

    // Animate gauge fill
    const gaugeFill = document.getElementById('gaugeFill');
    if (gaugeFill) {
        const circumference = 502; // 2 * PI * 80
        const offset = circumference - (circumference * score / 100);
        setTimeout(() => {
            gaugeFill.style.strokeDashoffset = offset;
        }, 100);
    }

    // Set grade
    const gradeEl = document.getElementById('scoreGrade');
    if (gradeEl) {
        gradeEl.textContent = getScoreGrade(score);
    }

    // Target progress
    const targetFill = document.getElementById('targetFill');
    const targetValue = document.getElementById('targetValue');
    if (targetFill && targetValue) {
        const progress = Math.min((score / target) * 100, 100);
        targetFill.style.width = `${progress}%`;
        targetValue.textContent = target;
    }
}

function getScoreGrade(score) {
    if (score >= 90) return 'A - Excellent';
    if (score >= 80) return 'B - Good';
    if (score >= 70) return 'C - Fair';
    if (score >= 60) return 'D - Needs Work';
    return 'F - Critical';
}

function animateScoreIncrease(points) {
    const popup = document.getElementById('scorePopup');
    const popupValue = document.getElementById('scorePopupValue');

    if (popup && popupValue) {
        popupValue.textContent = `+${points}`;
        popup.classList.add('show');

        setTimeout(() => {
            popup.classList.remove('show');
        }, 2000);
    }
}

function animateNumber(element, start, end, duration) {
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (end - start) * eased);

        element.textContent = current;

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

// ============================================================================
// QUICK STATS
// ============================================================================

function renderQuickStats(stats) {
    const completed = stats.tasks_completed || 0;
    const total = stats.tasks_total || 0;
    const inProgress = stats.tasks_in_progress || 0;
    const remaining = total - completed - inProgress;

    document.getElementById('statCompleted').textContent = completed;
    document.getElementById('statInProgress').textContent = inProgress;
    document.getElementById('statRemaining').textContent = remaining;

    // Quick win
    if (stats.next_quick_win) {
        document.getElementById('statQuickWin').textContent = `+${stats.next_quick_win.score_impact || 5}`;
        document.getElementById('quickWinTitle').textContent = truncate(stats.next_quick_win.task_name, 20);
    }
}

// ============================================================================
// SCAN BANNER
// ============================================================================

function renderScanBanner(stats) {
    const banner = document.getElementById('scanBanner');
    if (!banner) return;

    if (stats.scan_findings_count > 0) {
        document.getElementById('scanBannerText').textContent =
            `We found ${stats.scan_findings_count} issues from your latest XASM scan.`;
        banner.style.display = 'flex';
    } else {
        banner.style.display = 'none';
    }
}

async function importScanFindings() {
    try {
        const response = await fetch(`${API_URL}/api/roadmap/import-scans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            showNotification('success', `Imported ${data.tasks_created} tasks from scan findings.`);
            await loadDashboard();
        }
    } catch (error) {
        console.error('[Roadmap] Error importing scans:', error);
    }
}

// ============================================================================
// ACHIEVEMENTS
// ============================================================================

async function loadAchievements() {
    try {
        const response = await fetch(`${API_URL}/api/roadmap/achievements`);
        return await response.json();
    } catch (error) {
        console.error('[Roadmap] Error loading achievements:', error);
        return { achievements: [], available: [] };
    }
}

function renderAchievements(data) {
    const grid = document.getElementById('achievementsGrid');
    if (!grid) return;

    const unlocked = data.achievements || [];
    const available = data.available || [];

    const allAchievements = [
        ...unlocked.map(a => ({ ...a, unlocked: true })),
        ...available.map(a => ({ ...a, unlocked: false }))
    ];

    if (allAchievements.length === 0) {
        grid.innerHTML = `
            <div class="achievement-card locked">
                <span class="achievement-icon">?</span>
                <div class="achievement-name">Complete tasks to unlock!</div>
                <div class="achievement-desc">Your first achievement awaits</div>
            </div>
        `;
        return;
    }

    grid.innerHTML = allAchievements.map(ach => `
        <div class="achievement-card ${ach.unlocked ? 'unlocked' : 'locked'}">
            <span class="achievement-icon">${ach.unlocked ? getAchievementIcon(ach.achievement_icon || ach.icon) : '?'}</span>
            <div class="achievement-name">${escapeHtml(ach.achievement_name)}</div>
            <div class="achievement-desc">${escapeHtml(ach.achievement_description || ach.requirement || '')}</div>
        </div>
    `).join('');
}

function getAchievementIcon(icon) {
    const icons = {
        'trophy': '&#127942;',
        'zap': '&#9889;',
        'shield': '&#128737;',
        'award': '&#127941;',
        'star': '&#11088;',
        'check-circle': '&#9989;',
        'lock': '&#128274;',
        'check-square': '&#9745;',
        'calendar': '&#128197;',
        'alert-triangle': '&#9888;'
    };
    return icons[icon] || '&#127942;';
}

function showAchievementUnlock(achievementId) {
    // Create toast notification for achievement
    const toast = document.createElement('div');
    toast.className = 'achievement-toast';
    toast.innerHTML = `
        <div style="display: flex; align-items: center; gap: 16px; background: linear-gradient(135deg, rgba(212,175,55,0.2), rgba(0,0,0,0.9)); border: 2px solid var(--gold-primary); border-radius: 12px; padding: 16px 24px;">
            <span style="font-size: 2rem;">&#127942;</span>
            <div>
                <div style="color: var(--gold-primary); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.1em;">Achievement Unlocked!</div>
                <div style="color: var(--text-primary); font-size: 1.1rem; font-weight: 600;">${achievementId}</div>
            </div>
        </div>
    `;
    toast.style.cssText = 'position: fixed; bottom: 24px; right: 24px; z-index: 3000; animation: slideIn 0.5s ease;';

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slideOut 0.5s ease';
        setTimeout(() => toast.remove(), 500);
    }, 4000);
}

// ============================================================================
// PROGRESS CHART
// ============================================================================

async function loadProgress() {
    try {
        const response = await fetch(`${API_URL}/api/roadmap/progress`);
        return await response.json();
    } catch (error) {
        console.error('[Roadmap] Error loading progress:', error);
        return { history: [] };
    }
}

function renderProgressChart(data) {
    const canvas = document.getElementById('progressChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const history = data.history || [];

    // Generate labels and data
    const labels = history.length > 0
        ? history.map(h => formatDate(h.date))
        : ['No data'];
    const scores = history.length > 0
        ? history.map(h => h.security_score)
        : [0];

    if (progressChart) {
        progressChart.destroy();
    }

    progressChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Security Score',
                data: scores,
                borderColor: '#D4AF37',
                backgroundColor: 'rgba(212, 175, 55, 0.1)',
                borderWidth: 3,
                tension: 0.4,
                fill: true,
                pointRadius: 6,
                pointHoverRadius: 8,
                pointBackgroundColor: '#D4AF37',
                pointBorderColor: '#050508',
                pointBorderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: { color: '#8B8D94' },
                    grid: { color: 'rgba(255,255,255,0.05)' }
                },
                x: {
                    ticks: { color: '#8B8D94' },
                    grid: { color: 'rgba(255,255,255,0.05)' }
                }
            }
        }
    });
}

// ============================================================================
// ROADMAP GENERATION
// ============================================================================

async function generateRoadmap() {
    const form = document.getElementById('setupForm');
    if (!form) return;

    const profileData = {
        industry: document.getElementById('industry').value,
        company_size: document.getElementById('companySize').value,
        target_score: parseInt(document.getElementById('targetScore').value) || 85
    };

    showLoading(true, 'Generating your roadmap...');

    try {
        // Save profile
        await saveProfile(profileData);

        // Generate roadmap
        const response = await fetch(`${API_URL}/api/roadmap/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ include_scans: true })
        });

        if (!response.ok) throw new Error('Failed to generate roadmap');

        // Reload dashboard
        await loadProfile();

    } catch (error) {
        console.error('[Roadmap] Error generating roadmap:', error);
        showNotification('error', 'Failed to generate roadmap. Please try again.');
    } finally {
        showLoading(false);
    }
}

// ============================================================================
// UI HELPERS
// ============================================================================

function showLoading(show, message = 'Loading...') {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        if (show) {
            overlay.classList.add('active');
            const textEl = overlay.querySelector('.loading-text');
            if (textEl) textEl.textContent = message;
        } else {
            overlay.classList.remove('active');
        }
    }
}

function showEmptyState() {
    document.getElementById('emptyState').style.display = 'block';
    document.getElementById('roadmapContent').style.display = 'none';
    showLoading(false);
}

function showNotification(type, message) {
    const colors = {
        success: '#00E676',
        warning: '#FDD835',
        error: '#E53935',
        info: '#42A5F5'
    };

    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 24px;
        right: 24px;
        padding: 16px 24px;
        background: rgba(0,0,0,0.9);
        border: 1px solid ${colors[type] || colors.info};
        border-radius: 8px;
        color: ${colors[type] || colors.info};
        font-size: 0.9rem;
        z-index: 3000;
        animation: slideIn 0.3s ease;
    `;
    notification.textContent = message;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function truncate(str, length) {
    if (!str) return '';
    return str.length > length ? str.substring(0, length) + '...' : str;
}

function formatDate(dateStr) {
    try {
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch {
        return dateStr;
    }
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

// Filter button clicks
document.addEventListener('click', (e) => {
    if (e.target.matches('.filter-btn')) {
        const filter = e.target.dataset.filter;
        if (filter) filterTasks(filter);
    }
});

// Chart period buttons
document.addEventListener('click', (e) => {
    if (e.target.matches('.chart-period-btn')) {
        document.querySelectorAll('.chart-period-btn').forEach(btn => btn.classList.remove('active'));
        e.target.classList.add('active');
        // Could reload chart with different period here
    }
});

// Modal close on overlay click
document.addEventListener('click', (e) => {
    if (e.target.matches('.modal-overlay')) {
        closeTaskModal();
    }
});

// Modal close on Escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeTaskModal();
    }
});

// Form submission
document.addEventListener('submit', (e) => {
    if (e.target.matches('#setupForm')) {
        e.preventDefault();
        generateRoadmap();
    }
});

// CSS Animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Export functions for global access
window.togglePhase = togglePhase;
window.filterTasks = filterTasks;
window.openTaskModal = openTaskModal;
window.closeTaskModal = closeTaskModal;
window.markTaskComplete = markTaskComplete;
window.verifyTaskFix = verifyTaskFix;
window.markCurrentTaskComplete = markCurrentTaskComplete;
window.importScanFindings = importScanFindings;
window.generateRoadmap = generateRoadmap;
