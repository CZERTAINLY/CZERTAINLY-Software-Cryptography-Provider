package com.czertainly.cp.soft.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;

/**
 * Helper class for calculating checksums of files.
 * And for storing the checksums of the Java-based migrations.
 * Inspired by <a href="https://github.com/zaunerc/flyway-checksum-tool">flyway-checksum-tool</a>
 */
public class DatabaseMigration {

    /**
     * Calculates the checksum of a file.
     *
     * @param filePath The path to the file.
     * @return The checksum of the file.
     */
    public static int calculateChecksum(String filePath) throws IOException {
        final File file = new File(filePath);
        final CRC32 crc32 = new CRC32();

        try (FileReader fileReader = new FileReader(file); BufferedReader bufferedReader = new BufferedReader(fileReader, 4096)) {
            String line;
            boolean firstLineProcessed = false;
            while ((line = bufferedReader.readLine()) != null) {
                if (!firstLineProcessed) {
                    line = filterBomFromString(line);
                    firstLineProcessed = true;
                }
                String trimmed = trimLineBreak(line);
                crc32.update(trimmed != null ? trimmed.getBytes(StandardCharsets.UTF_8) : new byte[0]);
            }
        }
        return (int) crc32.getValue();
    }

    /**
     * Stores the checksum of a Java-based migration.
     */
    @SuppressWarnings("java:S115")
    public enum JavaMigrationChecksums {
        V202505021400__RemoveDeprecatedKeysFromKeystore(1418544588);


        private final int checksum;

        private final boolean isAltered;

        JavaMigrationChecksums(int checksum) {
            this(checksum, false);
        }

        JavaMigrationChecksums(int checksum, boolean isAltered) {
            this.checksum = checksum;
            this.isAltered = isAltered;
        }

        public int getChecksum() {
            return checksum;
        }

        public boolean isAltered() {
            return isAltered;
        }
    }

    private static final char BOM = '\ufeff';

    /**
     * Determine if this char is a UTF-8 Byte Order Mark
     *
     * @param c The char to check
     * @return Whether this char is a UTF-8 Byte Order Mark
     */
    public static boolean isBom(char c) {
        return c == BOM;
    }

    /**
     * Removes the UTF-8 Byte Order Mark from the start of a string if present.
     *
     * @param s The string
     * @return The string without a Byte Order Mark at the start
     */
    public static String filterBomFromString(String s) {
        if (s.isEmpty()) {
            return s;
        }

        if (isBom(s.charAt(0))) {
            return s.substring(1);
        }

        return s;
    }

    /**
     * Trim the trailing linebreak (if any) from this string.
     *
     * @param str The string.
     * @return The string without trailing linebreak.
     */
    public static String trimLineBreak(String str) {
        if (!hasLength(str)) {
            return str;
        }
        StringBuilder buf = new StringBuilder(str);
        while (buf.length() > 0 && isLineBreakCharacter(buf.charAt(buf.length() - 1))) {
            buf.deleteCharAt(buf.length() - 1);
        }
        return buf.toString();
    }

    /**
     * Checks whether this string is not {@code null} and not <i>empty</i>.
     *
     * @param str The string to check.
     * @return {@code true} if it has content, {@code false} if it is {@code null} or blank.
     */
    public static boolean hasLength(String str) {
        return str != null && !str.isEmpty();
    }

    /**
     * Checks whether this character is a linebreak character.
     *
     * @param ch The character
     * @return {@code true} if it is, {@code false} if not.
     */
    private static boolean isLineBreakCharacter(char ch) {
        return '\n' == ch || '\r' == ch;
    }
}