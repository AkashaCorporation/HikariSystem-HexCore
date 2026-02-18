/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Risk level type used across HexCore extensions for visual indicators.
 */
export type RiskLevel = 'safe' | 'warning' | 'danger';

/**
 * Maps a risk level to its corresponding hex color.
 * - safe    → #4ec9b0 (green)
 * - warning → #dcdcaa (yellow)
 * - danger  → #f44747 (red)
 */
export function riskLevelToColor(level: RiskLevel): string {
	switch (level) {
		case 'safe': return '#4ec9b0';
		case 'warning': return '#dcdcaa';
		case 'danger': return '#f44747';
	}
}

/**
 * Maps a Shannon entropy value (0.0–8.0) to a color.
 * - green  #4ec9b0  for values < 5.0
 * - yellow #dcdcaa  for values >= 5.0 and <= 7.0
 * - red    #f44747  for values > 7.0
 */
export function entropyToColor(value: number): string {
	if (value < 5.0) {
		return '#4ec9b0';
	}
	if (value <= 7.0) {
		return '#dcdcaa';
	}
	return '#f44747';
}
