interface Device {
    ip: string;
    mac: string;
    blocked: boolean;
    hostname: string;
}

interface ScanResponse {
    devices: Device[];
}

interface StatusResponse {
    blocked: Record<string, { blocked: boolean; duration: number }>;
    gateway: string;
    local_ip: string;
}

interface ActionResponse {
    status: string;
    ip: string;
    error?: string;
}

class ARPControllerApp {
    private devices: Device[] = [];
    private scanning: boolean = false;

    private escapeHtml(str: string): string {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    constructor() {
        this.loadStatus();
    }

    private async fetchJSON<T>(url: string, options?: RequestInit): Promise<T> {
        const response = await fetch(url, options);
        if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            throw new Error(body.error || `HTTP ${response.status}`);
        }
        return response.json();
    }

    async scan(): Promise<void> {
        if (this.scanning) return;
        this.scanning = true;
        const btn = document.getElementById("scanBtn") as HTMLButtonElement;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span>스캔 중...';

        try {
            const data = await this.fetchJSON<ScanResponse>("/api/scan");
            this.devices = data.devices;
            this.render();
            this.showToast(`스캔 완료: ${this.devices.length}대 발견`, "success");
        } catch (err) {
            this.showToast(`스캔 실패: ${(err as Error).message}`, "error");
        } finally {
            this.scanning = false;
            btn.disabled = false;
            btn.textContent = "네트워크 스캔";
        }
    }

    async block(ip: string): Promise<void> {
        const btn = document.querySelector(`[data-block="${ip}"]`) as HTMLButtonElement;
        if (btn) { btn.disabled = true; btn.textContent = "차단 중..."; }

        try {
            await this.fetchJSON<ActionResponse>("/api/block", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ip }),
            });
            const device = this.devices.find(d => d.ip === ip);
            if (device) device.blocked = true;
            this.render();
            this.showToast(`${ip} 인터넷 차단됨`, "info");
        } catch (err) {
            this.showToast(`차단 실패: ${(err as Error).message}`, "error");
            if (btn) { btn.disabled = false; btn.textContent = "인터넷 차단"; }
        }
    }

    async unblock(ip: string): Promise<void> {
        const btn = document.querySelector(`[data-unblock="${ip}"]`) as HTMLButtonElement;
        if (btn) { btn.disabled = true; btn.textContent = "복구 중..."; }

        try {
            await this.fetchJSON<ActionResponse>("/api/unblock", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ip }),
            });
            const device = this.devices.find(d => d.ip === ip);
            if (device) device.blocked = false;
            this.render();
            this.showToast(`${ip} 인터넷 복구됨`, "success");
        } catch (err) {
            this.showToast(`복구 실패: ${(err as Error).message}`, "error");
            if (btn) { btn.disabled = false; btn.textContent = "인터넷 허용"; }
        }
    }

    async loadStatus(): Promise<void> {
        try {
            const data = await this.fetchJSON<StatusResponse>("/api/status");
            const localEl = document.getElementById("localInfo");
            const gwEl = document.getElementById("gatewayInfo");
            if (localEl) localEl.textContent = `로컬: ${data.local_ip || "-"}`;
            if (gwEl) gwEl.textContent = `게이트웨이: ${data.gateway || "-"}`;
        } catch {
            // server may not be ready
        }
    }

    render(): void {
        const tbody = document.getElementById("deviceList")!;
        const countEl = document.getElementById("deviceCount")!;

        countEl.textContent = String(this.devices.length);

        if (this.devices.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="empty-state">
                <div class="emoji">🔍</div>
                <p>네트워크 스캔을 클릭하여 기기를 검색하세요</p>
            </td></tr>`;
            return;
        }

        tbody.innerHTML = this.devices.map(d => `
            <tr class="${d.blocked ? "blocked" : ""}">
                <td class="ip-cell">${this.escapeHtml(d.ip)}</td>
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
                        : `<button class="toggle-btn toggle-block" data-block="${this.escapeHtml(d.ip)}" onclick="app.block('${this.escapeHtml(d.ip)}')">인터넷 차단</button>`
                    }
                </td>
            </tr>
        `).join("");
    }

    private showToast(message: string, type: "success" | "error" | "info"): void {
        const toast = document.getElementById("toast")!;
        toast.textContent = message;
        toast.className = `toast toast-${type} show`;
        setTimeout(() => {
            toast.className = "toast";
        }, 3000);
    }
}

const app = new ARPControllerApp();
