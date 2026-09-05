export const MAX_VIRTUAL_SCROLL_HEIGHT = 8_000_000;

export function getVirtualScrollHeight(totalRows: number, rowHeight: number): number {
	if (!Number.isFinite(totalRows) || !Number.isFinite(rowHeight) || totalRows <= 0 || rowHeight <= 0) {
		return 0;
	}
	return Math.min(totalRows * rowHeight, MAX_VIRTUAL_SCROLL_HEIGHT);
}
