import type { PendingGrant } from "./types.js";

export class VaultClient {
  constructor(
    private readonly baseUrl: string = "http://127.0.0.1:7077",
    private readonly token?: string,
  ) {}

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.token) {
      h["Authorization"] = `Bearer ${this.token}`;
    }
    return h;
  }

  async health(): Promise<boolean> {
    try {
      const res = await fetch(`${this.baseUrl}/health`);
      return res.ok;
    } catch {
      return false;
    }
  }

  async getPending(): Promise<PendingGrant[]> {
    try {
      const res = await fetch(`${this.baseUrl}/grants/pending`, {
        headers: this.headers(),
      });
      if (!res.ok) return [];
      const data = await res.json() as unknown;
      if (Array.isArray(data)) {
        return data as PendingGrant[];
      }
      return [];
    } catch {
      return [];
    }
  }

  async approveGrant(grantId: string): Promise<boolean> {
    try {
      const res = await fetch(`${this.baseUrl}/grants/approve`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify({ grantId }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  async revokeTarget(target: string): Promise<boolean> {
    try {
      const res = await fetch(`${this.baseUrl}/grants/revoke`, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify({ target }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}
