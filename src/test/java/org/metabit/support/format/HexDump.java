/*
 *  published as part of the SAFEsealing package by S.A.F.E. e.V.; taken from mUtils library.
 *  written 2018-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package org.metabit.support.format;

/**
 * <p>HexDump class.</p>
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public class HexDump
{
    static final String   HEXES  = "0123456789ABCDEF";
    /**
     * the simple, low-effort hex dump, with some flexibility.
     * hex print byte input into String.
     *
     * @param raw raw input bytes to print
     * @param separator      the separator between the byte chars. May be an empty string.
     * @param entriesPerLine how many bytes may fit into a single line until we add a line break
     * @return the formatted string
     */
    public static String bytesToHexString(byte[] raw, String separator, int entriesPerLine)
        {
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        int                 pos = 0;

        for (final byte b : raw) // this seems to over-extend in buffers.
            {
            hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
            hex.append(separator);
            pos++;
            if ((entriesPerLine > 0) && (pos >= entriesPerLine))
                {
                pos = 0;
                hex.append(System.lineSeparator());
                }
            }
        return hex.toString();
        }
}
