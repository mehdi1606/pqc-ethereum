"""Regenerates Figs. 1-5 of the paper at 600 dpi (PNG) from results/*.
Fig. 1 architecture, Fig. 2 protocol sequence, Fig. 3 measured gas breakdown,
Fig. 4 analytical metrics vs [12], Fig. 5 on-chain gas per record vs batch size.
Run: python scripts/make_figures.py
"""
import csv, json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R, F = os.path.join(ROOT, "results"), os.path.join(ROOT, "figures")
os.makedirs(F, exist_ok=True)
DPI = 600
plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"], "font.size": 7,
                     "axes.edgecolor": "#52514e", "axes.labelcolor": "#0b0b0b", "xtick.color": "#52514e",
                     "ytick.color": "#52514e", "axes.linewidth": 0.6, "savefig.facecolor": "white"})
BLUE, ORANGE, AQUA, YELLOW = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
M = json.load(open(os.path.join(R, "metrics.json")))


def rcsv(n):
    return list(csv.DictReader(open(os.path.join(R, n), newline="")))


def box(ax, x, y, w, h, text, fc="#ffffff", ec=INK2, fs=6.2, bold=False, lw=0.7):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.004,rounding_size=0.012", fc=fc, ec=ec, lw=lw))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=INK,
            fontweight="bold" if bold else "normal", linespacing=1.15)


def arrow(ax, a, b, text=None, color=INK2, fs=5.6, rad=0.0, off=(0, 0.012), ls="-"):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=6, lw=0.7, color=color,
                                 connectionstyle=f"arc3,rad={rad}", linestyle=ls))
    if text:
        ax.text((a[0] + b[0]) / 2 + off[0], (a[1] + b[1]) / 2 + off[1], text, ha="center", va="bottom",
                fontsize=fs, color=INK2)


# ------------------------------------------------------------------ Fig. 1
def fig1():
    fig = plt.figure(figsize=(3.45, 3.3))
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    # layers
    ax.add_patch(FancyBboxPatch((0.01, 0.40), 0.98, 0.585, boxstyle="round,pad=0,rounding_size=0.015", fc="#f3f7fd", ec=BLUE, lw=0.8))
    ax.text(0.03, 0.965, "OFF-CHAIN (signer client / any verifier, liboqs)", fontsize=6.4, color=BLUE, fontweight="bold", va="top")
    ax.add_patch(FancyBboxPatch((0.01, 0.01), 0.98, 0.36, boxstyle="round,pad=0,rounding_size=0.015", fc="#fdf4ef", ec=ORANGE, lw=0.8))
    ax.text(0.03, 0.022, "ON-CHAIN (Ethereum, PQCAnchor.sol)", fontsize=6.4, color="#b4461b", fontweight="bold", va="bottom")
    # signer column (x 0.08-0.33; the registration arrow runs in the free lane at x = 0.045)
    box(ax, 0.08, 0.80, 0.25, 0.12, "Key generation (once)\nML-DSA-65 + Falcon-512\nkeyId = H(pk_D, pk_F)", fs=5.8)
    box(ax, 0.08, 0.62, 0.25, 0.14, "Dual signing (both\nmandatory) over\nμ = enc(DST, chainId,\naddr, nonce, keyId, H(m))", fs=5.6)
    box(ax, 0.08, 0.45, 0.25, 0.13, "Commitment C =\nH(abi.encode(DST, ...,\nσ_D, σ_F, keyId, H(m)))", fs=5.6)
    box(ax, 0.36, 0.80, 0.27, 0.12, "Optional ML-KEM-768\nEncaps + HKDF + AES-GCM\n(encrypt-then-sign)", fc="#fffbea", ec=YELLOW, fs=5.8)
    box(ax, 0.36, 0.55, 0.27, 0.20, "IPFS / Arweave\n(content-addressed)\n• pk bundle + PoP\n• record (m, σ_D, σ_F)\n• batch manifest + proofs", fc="#ffffff", fs=5.8)
    box(ax, 0.66, 0.60, 0.31, 0.32, "Verifier (anyone)\n1. fetch record, keys\n2. recompute keyId, C\n3. Verify_D AND Verify_F\n4. keyId = registry entry\n    registered before anchor\n5. C anchored, or Merkle\n    proof to anchored root", fs=5.7)
    box(ax, 0.36, 0.42, 0.27, 0.09, "Merkle batching (N)\nroot over leaves H(H(C))", fs=5.8)
    arrow(ax, (0.205, 0.80), (0.205, 0.76)); arrow(ax, (0.205, 0.62), (0.205, 0.58))
    arrow(ax, (0.36, 0.84), (0.33, 0.72))
    arrow(ax, (0.33, 0.66), (0.36, 0.64)); arrow(ax, (0.33, 0.49), (0.36, 0.47))
    arrow(ax, (0.63, 0.68), (0.66, 0.70))
    # on-chain
    box(ax, 0.03, 0.075, 0.30, 0.20, "PQ key registry\nregisterPQKey(keyId, pkCID)\nrotatePQKey / revokePQKey\n(authRef = PQ-signed\nauthorisation)", fc="#ffffff", ec=ORANGE, fs=5.8)
    box(ax, 0.36, 0.075, 0.27, 0.20, "Commitment log\nanchorCommitment(C,\n  nonce, cid)\nanchorBatchRoot(root,\n  n, manifestCID)", fc="#ffffff", ec=ORANGE, fs=5.8)
    box(ax, 0.66, 0.075, 0.31, 0.20, "verifyInclusion(leaf,\n  proof, root) (view)\nEvents: KeyRegistered,\nKeyRotated, Commitment-\nAnchored, BatchAnchored", fc="#ffffff", ec=ORANGE, fs=5.8)
    ax.plot([0.08, 0.045], [0.84, 0.84], color=INK2, lw=0.7)
    arrow(ax, (0.045, 0.84), (0.045, 0.275))
    ax.text(0.052, 0.62, "registration (ECDSA tx)", fontsize=5.0, color=INK2, rotation=90, va="center")
    arrow(ax, (0.24, 0.45), (0.45, 0.275))
    ax.text(0.155, 0.418, "anchor: ECDSA tx, 32 B", fontsize=5.0, color=INK2, ha="center")
    arrow(ax, (0.50, 0.42), (0.50, 0.275))
    arrow(ax, (0.80, 0.275), (0.80, 0.60))
    ax.text(0.815, 0.47, "eth_call", fontsize=5.4, color=INK2)
    fig.savefig(os.path.join(F, "fig1_architecture.png"), dpi=DPI); plt.close(fig)


# ------------------------------------------------------------------ Fig. 2
def fig2():
    fig = plt.figure(figsize=(3.45, 3.45))
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    lanes = {"Signer": 0.165, "IPFS": 0.40, "PQCAnchor": 0.63, "Verifier": 0.855}
    for n, x in lanes.items():
        box(ax, x - 0.105, 0.94, 0.21, 0.045, n, bold=True, fs=6.4)
        ax.plot([x, x], [0.02, 0.94], color=GRID, lw=0.9, zorder=0)
    S, I, C, V = lanes["Signer"], lanes["IPFS"], lanes["PQCAnchor"], lanes["Verifier"]
    y = [0.90]
    def step(a, b, t, dy=0.062, color=INK2, ls="-"):
        arrow(ax, (a, y[0]), (b, y[0]), t, color=color, ls=ls, off=(0, 0.004)); y[0] -= dy
    def note(x, t, dy=0.05, w=0.30):
        x0 = min(max(x - w / 2, 0.01), 0.99 - w); box(ax, x0, y[0] - 0.022, w, 0.044, t, fc="#f3f7fd", ec=BLUE, fs=5.4); y[0] -= dy
    note(S, "0. KeyGen_D, KeyGen_F; PoP", w=0.30)
    step(S, I, "pk_D, pk_F, PoP sigs")
    step(S, C, "registerPQKey(keyId, pkCID)", color="#b4461b")
    note(S, "1-3. serialise m (abi); [Kyber\nencrypt]; σ_D, σ_F over μ", dy=0.07, w=0.30)
    note(S, "4. C = H(abi.encode(...))", w=0.30)
    step(S, I, "record (m, σ_D, σ_F, keyId)")
    step(S, C, "anchorCommitment(C, nonce, cid)", color="#b4461b")
    note(C, "store (block, nonce);\nemit CommitmentAnchored", dy=0.07, w=0.30)
    ax.plot([0.02, 0.98], [y[0] + 0.012, y[0] + 0.012], color=INK2, lw=0.5, ls="--")
    ax.text(0.03, y[0] - 0.002, "verification (any third party)", fontsize=5.6, color=INK2, style="italic"); y[0] -= 0.035
    step(V, I, "fetch record, key bundle")
    step(V, C, "eth_call accounts(), commitments()")
    note(V, "recompute keyId, C;\nVerify_D AND Verify_F", dy=0.07, w=0.30)
    note(V, "keyId = registry and\nregistered < anchor block", dy=0.07, w=0.30)
    box(ax, 0.40, y[0] - 0.035, 0.58, 0.06, "any check fails → reject (tampered m, foreign\nPQ key, wrong chainId/contract, unanchored C)",
        fc="#fdf1f1", ec="#e34948", fs=5.4)
    fig.savefig(os.path.join(F, "fig2_sequence.png"), dpi=DPI); plt.close(fig)


# ------------------------------------------------------------------ Fig. 3
def fig3():
    rows = rcsv("gas_trace_anchor.csv")
    comp = [(r["component"], int(r["gas"])) for r in rows if not r["component"].startswith(("SUM", "gasUsed", "EIP-7623"))]
    total = sum(g for _, g in comp)
    assert total == M["gas"]["single"]
    nice = {"base transaction (intrinsic 21000)": "Intrinsic base (21,000)", "KECCAK256": "KECCAK256", "SLOAD": "SLOAD (3 cold + 3 warm)",
            "SSTORE": "SSTORE (20,000 + 2,900)", "LOG3": "LOG3 event", "other opcodes (stack/memory/control/calldata)": "Other opcodes"}
    lab = [nice.get(c, "Calldata (196 B)" if c.startswith("calldata") else c) for c, _ in comp]
    order = sorted(range(len(comp)), key=lambda i: comp[i][1])
    fig, ax = plt.subplots(figsize=(3.45, 1.9))
    vals = [comp[i][1] for i in order]
    ax.barh(range(len(order)), vals, color=BLUE, height=0.62)
    for k, v in enumerate(vals):
        ax.text(v + 300, k, f"{v:,} ({100*v/total:.1f}%)", va="center", fontsize=6.2, color=INK)
    ax.set_yticks(range(len(order))); ax.set_yticklabels([lab[i] for i in order])
    ax.set_xlim(0, 30500); ax.set_xlabel(f"Gas (measured total {total:,}; components sum exactly)")
    ax.xaxis.grid(True, color=GRID, lw=0.5); ax.set_axisbelow(True)
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    fig.tight_layout(); fig.savefig(os.path.join(F, "fig3_gas_breakdown.png"), dpi=DPI); plt.close(fig)


# ------------------------------------------------------------------ Fig. 4
def fig4():
    systems = ["This work", "[12] proposed", "SSCA [12]", "KES [12]"]
    qarl = [M["QARL_pct"], 90, 70, 60]
    qsm = [M["QSM_min_pct"], 95.8, 82.1, 74.3]
    coe = [100 * M["COE"]["COE_lambda_min"], 92, 74, 68]
    fig, ax = plt.subplots(figsize=(3.45, 2.0))
    w = 0.26
    for j, (vals, name, col) in enumerate([(qarl, "QARL (%)", BLUE), (qsm, "QSM (%)", ORANGE), (coe, "COE × 100", AQUA)]):
        xs = [i + (j - 1) * w for i in range(len(systems))]
        ax.bar(xs, vals, width=w - 0.03, color=col, label=name)
        for x, v in zip(xs, vals):
            ax.text(x, v + 1.5, f"{v:.0f}" if v >= 99.95 or abs(v - round(v)) < 0.05 else f"{v:.1f}", ha="center", fontsize=5.4, color=INK)
    ax.set_xticks(range(len(systems))); ax.set_xticklabels(systems)
    ax.set_ylim(0, 128); ax.set_ylabel("Metric value")
    ax.yaxis.grid(True, color=GRID, lw=0.5); ax.set_axisbelow(True)
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    ax.legend(ncol=3, fontsize=5.8, frameon=False, loc="upper center", bbox_to_anchor=(0.5, 1.12))
    ax.axvline(0.5, color=INK2, lw=0.5, ls=":")
    ax.text(0.55, 124, "values reported in [12] (Hyperledger;\ndifferent definitions and hardware)", fontsize=5.2, color=INK2, va="top")
    fig.tight_layout(); fig.savefig(os.path.join(F, "fig5_metrics_comparison.png"), dpi=DPI); plt.close(fig)


# ------------------------------------------------------------------ Fig. 5
def fig5():
    b = rcsv("gas_batch.csv"); inc = {int(r["N"]): int(r["verifyInclusionTx_gasUsed"]) for r in rcsv("gas_inclusion.csv")}
    N = [int(r["N"]) for r in b]; per = [float(r["gas_per_record"]) for r in b]
    fig, ax = plt.subplots(figsize=(3.45, 2.1))
    ax.plot(N, per, color=BLUE, lw=1.6, marker="o", ms=4, label="anchorBatchRoot gas / record")
    ax.plot(N, [inc[n] for n in N], color=ORANGE, lw=1.6, marker="s", ms=4, label="verifyInclusionTx gas (one record, on-chain)")
    ax.axhline(M["gas"]["single"], color=INK2, lw=0.8, ls="--")
    ax.text(1.15, M["gas"]["single"] * 1.45, f"single anchorCommitment = {M['gas']['single']:,}", fontsize=5.6, color=INK2)
    for n, p in zip(N, per):
        ax.text(n * 1.15, p * 0.62, f"{p:,.0f}" if p >= 10 else f"{p:.1f}", fontsize=5.6, color=INK)
    ax.set_xscale("log"); ax.set_yscale("log"); ax.set_ylim(2, 2.5e5)
    ax.set_xlabel("Batch size N (records per Merkle root)"); ax.set_ylabel("Gas (log scale)")
    ax.grid(True, which="major", color=GRID, lw=0.5); ax.set_axisbelow(True)
    for s in ("top", "right"): ax.spines[s].set_visible(False)
    ax.legend(fontsize=5.6, frameon=False, loc="lower left")
    fig.tight_layout(); fig.savefig(os.path.join(F, "fig4_batch_cost.png"), dpi=DPI); plt.close(fig)


for f in (fig1, fig2, fig3, fig4, fig5):
    f()
print("figures written to", F)
