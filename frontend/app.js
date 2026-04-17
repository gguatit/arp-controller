"use strict";
class ARPControllerApp {
    escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }
    constructor() {
        this.devices = [];
        this.scanning = false;
        this.detailOpen = false;
        this.toastTimer = null;
        this.pollTimer = null;
        this.loadStatus();
        this.setupDetailClose();
    }
    setupDetailClose() {
        const overlay = document.getElementById("detailOverlay");
        const closeBtn = document.getElementById("detailClose");
        if (overlay)
            overlay.addEventListener("click", () => this.closeDetail());
        if (closeBtn)
            closeBtn.addEventListener("click", () => this.closeDetail());
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape" && this.detailOpen)
                this.closeDetail();
        });
    }
    openDetail() {
        const overlay = document.getElementById("detailOverlay");
        const panel = document.getElementById("detailPanel");
        if (overlay)
            overlay.classList.add("active");
        if (panel)
            panel.classList.add("active");
        this.detailOpen = true;
    }
    closeDetail() {
        const overlay = document.getElementById("detailOverlay");
        const panel = document.getElementById("detailPanel");
        if (overlay)
            overlay.classList.remove("active");
        if (panel)
            panel.classList.remove("active");
        this.detailOpen = false;
    }
    async fetchJSON(url, options) {
        const response = await fetch(url, options);
        if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            throw new Error(body.error || `HTTP ${response.status}`);
        }
        return response.json();
    }
    async scan() {
        if (this.scanning)
            return;
        this.scanning = true;
        const btn = document.getElementById("scanBtn");
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span>스캔 중...';
        try {
            const data = await this.fetchJSON("/api/scan");
            this.devices = data.devices;
            this.render();
            if (data.scanning) {
                this.startPolling();
            }
            else {
                this.showToast(`스캔 완료: ${this.devices.length}대 발견`, "success");
            }
        }
        catch (err) {
            this.showToast(`스캔 실패: ${err.message}`, "error");
            this.scanning = false;
            btn.disabled = false;
            btn.textContent = "네트워크 스캔";
        }
    }
    startPolling() {
        if (this.pollTimer)
            clearInterval(this.pollTimer);
        this.pollTimer = setInterval(async () => {
            try {
                const data = await this.fetchJSON("/api/devices");
                this.devices = data.devices;
                this.render();
                if (!data.scanning) {
                    if (this.pollTimer)
                        clearInterval(this.pollTimer);
                    this.pollTimer = null;
                    this.scanning = false;
                    const btn = document.getElementById("scanBtn");
                    btn.disabled = false;
                    btn.textContent = "네트워크 스캔";
                    this.showToast(`스캔 완료: ${this.devices.length}대 발견`, "success");
                }
            }
            catch {
            }
        }, 1500);
    }
    async block(ip) {
        const btn = document.querySelector(`[data-block="${ip}"]`);
        if (btn) {
            btn.disabled = true;
            btn.textContent = "차단 중...";
        }
        try {
            await this.fetchJSON("/api/block", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ip }),
            });
            const device = this.devices.find(d => d.ip === ip);
            if (device)
                device.blocked = true;
            this.render();
            this.showToast(`${ip} 인터넷 차단됨`, "info");
        }
        catch (err) {
            this.showToast(`차단 실패: ${err.message}`, "error");
            if (btn) {
                btn.disabled = false;
                btn.textContent = "인터넷 차단";
            }
        }
    }
    async unblock(ip) {
        const btn = document.querySelector(`[data-unblock="${ip}"]`);
        if (btn) {
            btn.disabled = true;
            btn.textContent = "복구 중...";
        }
        try {
            await this.fetchJSON("/api/unblock", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ip }),
            });
            const device = this.devices.find(d => d.ip === ip);
            if (device)
                device.blocked = false;
            this.render();
            this.showToast(`${ip} 인터넷 복구됨`, "success");
        }
        catch (err) {
            this.showToast(`복구 실패: ${err.message}`, "error");
            if (btn) {
                btn.disabled = false;
                btn.textContent = "인터넷 허용";
            }
        }
    }
    async loadStatus() {
        try {
            const data = await this.fetchJSON("/api/status");
            const myIp = document.getElementById("myIp");
            const myMac = document.getElementById("myMac");
            const myGwIp = document.getElementById("myGwIp");
            const myGwMac = document.getElementById("myGwMac");
            if (myIp)
                myIp.textContent = data.local_ip || "-";
            if (myMac)
                myMac.textContent = data.local_mac || "-";
            if (myGwIp)
                myGwIp.textContent = data.gateway || "-";
            if (myGwMac)
                myGwMac.textContent = data.gateway_mac || "-";
        }
        catch {
        }
    }
    async showDeviceDetail(ip) {
        this.openDetail();
        const title = document.getElementById("detailTitle");
        const body = document.getElementById("detailBody");
        if (title)
            title.textContent = ip;
        if (body)
            body.innerHTML = '<div class="detail-spinner"><div class="spinner"></div></div>';
        try {
            const data = await this.fetchJSON(`/api/device?ip=${encodeURIComponent(ip)}`);
            if (body)
                body.innerHTML = this.renderDetail(data);
        }
        catch (err) {
            if (body)
                body.innerHTML = `<div class="detail-row"><div class="detail-val">조회 실패: ${err.message}</div></div>`;
        }
    }
    renderDetail(d) {
        const fmtDuration = (sec) => {
            const m = Math.floor(sec / 60);
            const s = Math.floor(sec % 60);
            if (m > 60)
                return `${Math.floor(m / 60)}시간 ${m % 60}분`;
            if (m > 0)
                return `${m}분 ${s}초`;
            return `${s}초`;
        };
        return `
            <div class="detail-row">
                <span class="detail-key">기기 유형</span>
                <span class="detail-val highlight">${this.escapeHtml(d.device_type)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-key">IP 주소</span>
                <span class="detail-val highlight">${this.escapeHtml(d.ip)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-key">MAC 주소</span>
                <span class="detail-val mono">${this.escapeHtml(d.mac)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-key">호스트명</span>
                <span class="detail-val">${d.hostname ? this.escapeHtml(d.hostname) : "-"}</span>
            </div>
            <div class="detail-row">
                <span class="detail-key">제조사</span>
                <span class="detail-val">${d.vendor ? this.escapeHtml(d.vendor) : "-"}</span>
            </div>
            <div class="detail-row">
                <span class="detail-key">OS 추정</span>
                <span class="detail-val">${this.escapeHtml(d.os_guess)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-key">TTL</span>
                <span class="detail-val">${d.ttl !== null ? d.ttl : "-"}</span>
            </div>
            <div class="detail-row">
                <span class="detail-key">응답 시간</span>
                <span class="detail-val">${d.rtt !== null ? d.rtt.toFixed(1) + " ms" : "-"}</span>
            </div>
            <div class="detail-row">
                <span class="detail-key">차단 상태</span>
                <span class="detail-val">${d.blocked_info ? "차단됨 (" + fmtDuration(d.blocked_info.duration) + ")" : "연결됨"}</span>
            </div>
        `;
    }
    render() {
        const tbody = document.getElementById("deviceList");
        const countEl = document.getElementById("deviceCount");
        countEl.textContent = String(this.devices.length);
        if (this.devices.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty-state">
                <div class="icon-placeholder"></div>
                <p>네트워크 스캔을 클릭하여 기기를 검색하세요</p>
            </td></tr>`;
            return;
        }
        tbody.innerHTML = this.devices.map(d => `
            <tr class="${d.blocked ? "blocked" : ""}">
                <td class="ip-cell" onclick="app.showDeviceDetail('${this.escapeHtml(d.ip)}')">${this.escapeHtml(d.ip)}${d.hostname ? `<span class="hostname-label">${this.escapeHtml(d.hostname)}</span>` : ""}${d.os_guess === "Scanning..." ? '<span class="os-pending">상세 검색 중...</span>' : ""}</td>
                <td class="mac-cell">${this.escapeHtml(d.mac)}</td>
                <td>
                    <span class="status-badge ${d.blocked ? "status-blocked" : "status-online"}">
                        <span class="status-dot"></span>
                        ${d.blocked ? "차단됨" : "연결됨"}
                    </span>
                </td>
                <td>
                    ${d.blocked
            ? `<button class="toggle-btn toggle-unblock" data-unblock="${this.escapeHtml(d.ip)}" onclick="app.unblock('${this.escapeHtml(d.ip)}')">인터넷 허용</button>`
            : `<button class="toggle-btn toggle-block" data-block="${this.escapeHtml(d.ip)}" onclick="app.block('${this.escapeHtml(d.ip)}')">인터넷 차단</button>`}
                </td>
            </tr>
        `).join("");
    }
    showToast(message, type) {
        const toast = document.getElementById("toast");
        if (this.toastTimer)
            clearTimeout(this.toastTimer);
        toast.textContent = message;
        toast.className = `toast toast-${type} show`;
        this.toastTimer = setTimeout(() => {
            toast.className = "toast";
            this.toastTimer = null;
        }, 3000);
    }
}
const app = new ARPControllerApp();
