import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.FileSystem;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.SleuthkitJNI;
import org.sleuthkit.datamodel.TskData;

/**
 * Post-timing verifier for a disposable synthetic Autopsy case, not an app benchmark.
 *
 * Usage: AutopsyCaseVerifier benchmark-root case.db specification.json NEW-export-directory
 * Run from the repository root. All arguments must be under local/autopsy-comparison.
 * The spec has synthetic:true, files:[{path,size,sha256,isDeleted,metaAddress?,
 * attributeType?,attributeID?,fsOffsetBytes?}], fsOffsetBytes?, timezone? and
 * sourcePaths:[absolute ordered segments of one synthetic image]. Files may include named data streams.
 * The caller sets tsk.tmpdir to an owned local directory and verifies the native load
 * trace. SleuthkitCase.openCase has no read-only mode and can initialize schema/locks;
 * therefore this program accepts only the caller's disposable benchmark case.
 * It never imports, ingests, sets hashes, or edits evidence. Only export files are
 * explicitly written. Output is one bounded JSON record on stdout, logs on stderr.
 */
public final class AutopsyCaseVerifier {
    private static final int MAX_FILES = 256;
    private static final int MAX_ROWS = 50_000;
    private static final long MAX_EXPORT_BYTES = 256L * 1024 * 1024;

    private static long number(JsonObject object, String field, long fallback) {
        if (!object.has(field)) return fallback;
        String value = object.get(field).getAsString();
        if (!value.matches("[0-9]+")) throw new IllegalArgumentException("Invalid " + field);
        return Long.parseLong(value);
    }

    private static String bounded(String text) {
        return text.length() <= 1024 ? text : text.substring(0, 1024);
    }

    private static String relativePath(String path) {
        while (path.startsWith("/")) path = path.substring(1);
        return path;
    }

    private static boolean deleted(AbstractFile file) {
        // A removed hard-link name can point to an allocated shared MFT record.
        return file.isDirNameFlagSet(TskData.TSK_FS_NAME_FLAG_ENUM.UNALLOC)
                || file.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.UNALLOC);
    }

    private static Path existingInside(Path root, String argument) throws Exception {
        Path path = Path.of(argument).toRealPath();
        if (!path.startsWith(root)) throw new IllegalArgumentException("Path outside owned benchmark root");
        return path;
    }

    private static Map<String, Object> describe(AbstractFile file) throws Exception {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("objectID", file.getId());
        row.put("path", bounded(relativePath(file.getParentPath() + file.getName())));
        row.put("name", bounded(file.getName()));
        row.put("size", file.getSize());
        row.put("isDeleted", deleted(file));
        row.put("nameFlags", file.getDirFlagAsString());
        row.put("metaFlags", file.getMetaFlagsAsString());
        row.put("isDirectory", file.isDir());
        row.put("isFile", file.isFile());
        row.put("nameType", file.getDirType().getValue());
        row.put("metaType", file.getMetaType().getValue());
        row.put("metaAddress", file.getMetaAddr());
        row.put("attributeType", file.getAttrType().getValue());
        row.put("attributeID", file.getAttributeId());
        FileSystem filesystem = file.getFileSystem();
        row.put("filesystem", filesystem.getFsType().toString());
        row.put("fsOffsetBytes", filesystem.getImageOffset());
        row.put("createdEpoch", file.getCrtime());
        row.put("modifiedEpoch", file.getMtime());
        row.put("changedEpoch", file.getCtime());
        row.put("accessedEpoch", file.getAtime());
        return row;
    }

    private static boolean matches(AbstractFile file, JsonObject expected, long defaultOffset) throws Exception {
        if (file.getFileSystem().getImageOffset() != number(expected, "fsOffsetBytes", defaultOffset)) return false;
        if (expected.has("metaAddress") && file.getMetaAddr() != number(expected, "metaAddress", 0)) return false;
        if (expected.has("attributeType") && file.getAttrType().getValue() != number(expected, "attributeType", 0)) return false;
        if (expected.has("attributeID") && file.getAttributeId() != number(expected, "attributeID", 0)) return false;
        String wanted = relativePath(expected.get("path").getAsString());
        String actual = relativePath(file.getParentPath() + file.getName());
        // The path disambiguates hard links that share all metadata and stream IDs.
        return wanted.equals(actual);
    }

    private static Map<String, Object> export(AbstractFile file, JsonObject expected,
                                               Path directory, int index) throws Exception {
        Map<String, Object> row = describe(file);
        long wantedSize = number(expected, "size", -1);
        String wantedHash = expected.get("sha256").getAsString();
        if (wantedSize < 0 || wantedSize > MAX_EXPORT_BYTES || !wantedHash.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid expected export size/hash");
        }
        if (file.getSize() != wantedSize) throw new IllegalStateException("Declared size differs from case row");
        if (expected.has("isDeleted") && deleted(file) != expected.get("isDeleted").getAsBoolean()) {
            throw new IllegalStateException("Declared allocation state differs from case row");
        }
        String filename = String.format("stream-%03d.bin", index);
        Path destination = directory.resolve(filename);
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[64 * 1024];
        long offset = 0;
        try (OutputStream output = Files.newOutputStream(destination,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            while (offset < wantedSize) {
                int requested = (int) Math.min(buffer.length, wantedSize - offset);
                int count = file.read(buffer, offset, requested);
                if (count <= 0 || count > requested) throw new IllegalStateException("Invalid/short content read at " + offset);
                output.write(buffer, 0, count);
                hash.update(buffer, 0, count);
                offset += count;
            }
        }
        String actualHash = HexFormat.of().formatHex(hash.digest());
        row.put("exportFile", filename);
        row.put("exportBytes", offset);
        row.put("sha256", actualHash);
        row.put("expectedSha256", wantedHash);
        row.put("passed", actualHash.equals(wantedHash) && Files.size(destination) == wantedSize);
        return row;
    }

    private static Map<String, Object> verify(String[] arguments) throws Exception {
        if (arguments.length != 4) throw new IllegalArgumentException("Expected benchmark-root case.db spec.json NEW-export-directory");
        Path allowed = Path.of("local", "autopsy-comparison").toRealPath();
        Path root = Path.of(arguments[0]).toRealPath();
        if (!root.startsWith(allowed)) throw new IllegalArgumentException("Benchmark root must be local/autopsy-comparison in this checkout");
        Path db = existingInside(root, arguments[1]);
        Path specPath = existingInside(root, arguments[2]);
        String nativeTemporaryDirectory = System.getProperty("tsk.tmpdir");
        if (nativeTemporaryDirectory == null
                || !Files.isDirectory(existingInside(root, nativeTemporaryDirectory))) {
            throw new IllegalArgumentException("tsk.tmpdir must be an existing owned benchmark directory");
        }
        if (!Files.isRegularFile(db, LinkOption.NOFOLLOW_LINKS) || Files.size(specPath) > 1024 * 1024) {
            throw new IllegalArgumentException("Expected regular database and bounded specification");
        }
        JsonObject spec = JsonParser.parseString(Files.readString(specPath)).getAsJsonObject();
        if (!spec.has("synthetic") || !spec.get("synthetic").getAsBoolean()) {
            throw new IllegalArgumentException("Only an explicitly synthetic specification is accepted");
        }
        JsonArray expected = spec.getAsJsonArray("files");
        if (expected == null || expected.size() < 1 || expected.size() > MAX_FILES) {
            throw new IllegalArgumentException("Expected between 1 and 256 declared payloads");
        }
        JsonArray sourcePaths = spec.getAsJsonArray("sourcePaths");
        if (sourcePaths == null || sourcePaths.size() < 1 || sourcePaths.size() > 32) {
            throw new IllegalArgumentException("Expected declared synthetic source paths");
        }
        Path destination = Path.of(arguments[3]).toAbsolutePath().normalize();
        Path parent = destination.getParent().toRealPath();
        if (!parent.startsWith(root) || Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Exports require an exact new child directory inside benchmark root");
        }
        // Avoid exporting through a symlinked parent component.
        destination = parent.resolve(destination.getFileName());
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("schemaVersion", 1);
        report.put("scope", "Post-timing synthetic case readback through Autopsy's ARM64-adapted TSK Java datamodel");
        report.put("architecture", System.getProperty("os.arch"));
        report.put("javaVersion", System.getProperty("java.version"));
        report.put("tskVersion", SleuthkitJNI.getVersion());
        report.put("datamodelOrigin", SleuthkitCase.class.getProtectionDomain().getCodeSource().getLocation().toString());
        List<Map<String, Object>> images = new ArrayList<>();
        List<Map<String, Object>> files = new ArrayList<>();
        boolean passed = true;
        SleuthkitCase sk = SleuthkitCase.openCase(db.toString(), null, null, false);
        try {
            List<String> declaredPaths = new ArrayList<>();
            for (JsonElement element : sourcePaths) declaredPaths.add(Path.of(element.getAsString()).toRealPath().toString());
            List<String> actualPaths = new ArrayList<>();
            List<Content> roots = sk.getRootObjects();
            if (roots.size() != 1) throw new IllegalStateException("Expected exactly one synthetic disk-image root");
            for (Content object : roots) {
                if (!(object instanceof Image image)) throw new IllegalStateException("Expected only disk-image roots");
                Map<String, Object> detail = new LinkedHashMap<>();
                detail.put("objectID", image.getId());
                detail.put("timezone", image.getTimeZone());
                detail.put("logicalSize", image.getSize());
                images.add(detail);
                for (String path : image.getPaths()) actualPaths.add(Path.of(path).toRealPath().toString());
                if (spec.has("timezone") && !spec.get("timezone").getAsString().equals(image.getTimeZone())) {
                    throw new IllegalStateException("Image timezone differs from specification");
                }
            }
            if (!actualPaths.equals(declaredPaths)) throw new IllegalStateException("Case source paths differ from declared synthetic images");
            List<AbstractFile> rows = sk.findAllFilesWhere("type = 0 ORDER BY obj_id LIMIT 50001");
            if (rows.size() > MAX_ROWS) throw new IllegalStateException("Case exceeds bounded filesystem listing");
            long deletedRows = rows.stream().filter(AutopsyCaseVerifier::deleted).count();
            report.put("filesystemRows", rows.size());
            report.put("deletedFilesystemRows", deletedRows);
            report.put("allocatedFilesystemRows", rows.size() - deletedRows);
            report.put("regularFilesystemRows", rows.stream().filter(AbstractFile::isFile).count());
            report.put("directoryFilesystemRows", rows.stream().filter(AbstractFile::isDir).count());
            Files.createDirectory(destination);
            long totalExpectedBytes = 0;
            int index = 0;
            for (JsonElement element : expected) {
                JsonObject wanted = element.getAsJsonObject();
                long wantedSize = number(wanted, "size", -1);
                totalExpectedBytes = Math.addExact(totalExpectedBytes, wantedSize);
                if (wantedSize < 0 || totalExpectedBytes > 1024L * 1024 * 1024) throw new IllegalArgumentException("Export set exceeds bound");
                List<AbstractFile> candidates = new ArrayList<>();
                for (AbstractFile row : rows) if (matches(row, wanted, number(spec, "fsOffsetBytes", 0))) candidates.add(row);
                Map<String, Object> detail;
                if (candidates.size() != 1) {
                    detail = new LinkedHashMap<>();
                    detail.put("path", bounded(wanted.get("path").getAsString()));
                    detail.put("matchedRows", candidates.size());
                    detail.put("passed", false);
                    detail.put("error", "Expected exactly one filesystem row for the declared path and stream identity");
                } else {
                    try {
                        detail = export(candidates.get(0), wanted, destination, index);
                    } catch (Exception failure) {
                        detail = describe(candidates.get(0));
                        detail.put("passed", false);
                        detail.put("error", bounded(failure.toString()));
                    }
                }
                passed &= Boolean.TRUE.equals(detail.get("passed"));
                files.add(detail);
                index++;
            }
        } finally {
            sk.close();
        }
        report.put("images", images);
        report.put("files", files);
        report.put("declaredPayloads", expected.size());
        report.put("verifiedPayloads", files.stream().filter(row -> Boolean.TRUE.equals(row.get("passed"))).count());
        report.put("passed", passed);
        return report;
    }

    public static void main(String[] arguments) {
        Map<String, Object> report;
        try {
            report = verify(arguments);
        } catch (Exception failure) {
            report = new LinkedHashMap<>();
            report.put("schemaVersion", 1);
            report.put("passed", false);
            report.put("error", bounded(failure.toString()));
            failure.printStackTrace(System.err);
        }
        String json = new Gson().toJson(report);
        if (json.length() > 512 * 1024) {
            System.out.println("{\"schemaVersion\":1,\"passed\":false,\"error\":\"Result exceeded bounded output\"}");
            System.exit(1);
        }
        System.out.println(json);
        if (!Boolean.TRUE.equals(report.get("passed"))) System.exit(1);
    }
}
