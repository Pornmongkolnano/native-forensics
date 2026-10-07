import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.SleuthkitJNI;
import org.sleuthkit.datamodel.TskData;

/** Direct datamodel correctness control. This is deliberately not a timing
 * benchmark. Only new, explicitly synthetic cases below local/autopsy-comparison
 * are accepted; source images are opened read-only by the datamodel. */
public final class AutopsyRepairProbe {
    private static native int environmentStackEntries();
    private static native String[] loadedTSKLibraries();

    private static String relative(String text) {
        return text.replaceFirst("^/+", "");
    }

    private static boolean deleted(AbstractFile file) {
        return file.isDirNameFlagSet(TskData.TSK_FS_NAME_FLAG_ENUM.UNALLOC)
                || file.isMetaFlagSet(TskData.TSK_FS_META_FLAG_ENUM.UNALLOC);
    }

    private static Map<String, Object> describe(AbstractFile file) throws Exception {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("objectID", file.getId());
        row.put("path", relative(file.getParentPath() + file.getName()));
        row.put("parentPath", relative(file.getParentPath()));
        row.put("name", file.getName());
        row.put("size", file.getSize());
        row.put("isDeleted", deleted(file));
        row.put("isDirectory", file.isDir());
        row.put("isFile", file.isFile());
        row.put("nameType", file.getDirType().getValue());
        row.put("metaType", file.getMetaType().getValue());
        row.put("metaAddress", file.getMetaAddr());
        row.put("attributeType", file.getAttrType().getValue());
        row.put("attributeID", file.getAttributeId());
        row.put("createdEpoch", file.getCrtime());
        row.put("modifiedEpoch", file.getMtime());
        row.put("changedEpoch", file.getCtime());
        row.put("accessedEpoch", file.getAtime());
        return row;
    }

    private static boolean matches(AbstractFile file, JsonObject expected) {
        if (!relative(file.getParentPath() + file.getName()).equals(expected.get("path").getAsString())) return false;
        if (expected.has("metaAddress") && file.getMetaAddr() != expected.get("metaAddress").getAsLong()) return false;
        if (expected.has("attributeType") && file.getAttrType().getValue() != expected.get("attributeType").getAsLong()) return false;
        return !expected.has("attributeID") || file.getAttributeId() == expected.get("attributeID").getAsInt();
    }

    private static Map<String, Object> execute(String[] args) throws Exception {
        if (args.length != 4) throw new IllegalArgumentException("Expected new-run-directory spec.json source-timezone environment-probe.dylib");
        Path allowed = Path.of("local", "autopsy-comparison").toRealPath();
        Path run = Path.of(args[0]).toRealPath();
        if (!run.startsWith(allowed)) throw new IllegalArgumentException("Run must be an owned benchmark child");
        Path specPath = Path.of(args[1]).toRealPath();
        Path probePath = Path.of(args[3]).toRealPath();
        Path tmp = Path.of(System.getProperty("tsk.tmpdir", "")).toRealPath();
        if (!specPath.startsWith(allowed) || !probePath.startsWith(allowed) || !tmp.startsWith(run)
                || Files.size(specPath) > 1024 * 1024) throw new IllegalArgumentException("Expected bounded owned inputs");
        JsonObject spec = JsonParser.parseString(Files.readString(specPath)).getAsJsonObject();
        if (!spec.has("synthetic") || !spec.get("synthetic").getAsBoolean()) throw new IllegalArgumentException("Expected synthetic specification");
        JsonArray sources = spec.getAsJsonArray("sourcePaths");
        JsonArray expected = spec.getAsJsonArray("files");
        if (sources == null || sources.size() != 1 || expected == null || expected.size() < 1 || expected.size() > 256) {
            throw new IllegalArgumentException("Control requires one synthetic image and 1-256 files");
        }
        Path source = Path.of(sources.get(0).getAsString()).toRealPath();
        if (!Files.isRegularFile(source) || Files.size(source) > 1024L * 1024 * 1024) throw new IllegalArgumentException("Expected bounded image");
        Path db = run.resolve("case.db");
        if (Files.exists(db, LinkOption.NOFOLLOW_LINKS)) throw new IllegalArgumentException("A new case is required");
        System.load(probePath.toString());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("scope", "Untimed synthetic TSK Java import and direct byte/metadata readback");
        result.put("timezone", args[2]);
        result.put("datamodelOrigin", SleuthkitCase.class.getProtectionDomain().getCodeSource().getLocation().toString());
        List<Map<String, Object>> files = new ArrayList<>();
        SleuthkitCase sk = SleuthkitCase.newCase(db.toString());
        try {
            result.put("beforeImportStackEnvironmentEntries", environmentStackEntries());
            SleuthkitJNI.CaseDbHandle.AddImageProcess process = sk.makeAddImageProcess(args[2], false, false, "");
            process.run("synthetic-repair-control", new String[] {source.toString()}, 0);
            result.put("afterImportStackEnvironmentEntries", environmentStackEntries());
            result.put("loadedTSKLibraries", loadedTSKLibraries());
            result.put("tskVersion", SleuthkitJNI.getVersion());
            List<AbstractFile> rows = sk.findAllFilesWhere("type = 0 ORDER BY obj_id LIMIT 50001");
            if (rows.size() > 50000) throw new IllegalStateException("Bounded listing exceeded");
            result.put("filesystemRows", rows.size());
            List<Map<String, Object>> directories = new ArrayList<>();
            for (AbstractFile row : rows) if (row.isDir()) directories.add(describe(row));
            result.put("directories", directories);
            for (JsonElement item : expected) {
                JsonObject wanted = item.getAsJsonObject();
                List<AbstractFile> candidates = new ArrayList<>();
                for (AbstractFile row : rows) if (matches(row, wanted)) candidates.add(row);
                Map<String, Object> detail = new LinkedHashMap<>();
                detail.put("path", wanted.get("path").getAsString());
                detail.put("matchedRows", candidates.size());
                if (candidates.size() == 1) {
                    AbstractFile file = candidates.get(0);
                    detail.putAll(describe(file));
                    long size = wanted.get("size").getAsLong();
                    if (size < 0 || size > 256L * 1024 * 1024 || file.getSize() != size) throw new IllegalStateException("Unexpected stream size");
                    MessageDigest hash = MessageDigest.getInstance("SHA-256");
                    byte[] buffer = new byte[65536];
                    long offset = 0;
                    while (offset < size) {
                        int count = file.read(buffer, offset, (int)Math.min(buffer.length, size - offset));
                        if (count <= 0 || count > Math.min(buffer.length, size - offset)) throw new IllegalStateException("Short stream read");
                        hash.update(buffer, 0, count);
                        offset += count;
                    }
                    detail.put("exportBytes", offset);
                    detail.put("sha256", HexFormat.of().formatHex(hash.digest()));
                }
                files.add(detail);
            }
            List<Map<String, Object>> images = new ArrayList<>();
            for (org.sleuthkit.datamodel.Content content : sk.getRootObjects()) {
                if (!(content instanceof Image image)) throw new IllegalStateException("Unexpected case root");
                Map<String, Object> imageDetail = new LinkedHashMap<>();
                imageDetail.put("timezone", image.getTimeZone());
                imageDetail.put("logicalSize", image.getSize());
                images.add(imageDetail);
            }
            result.put("images", images);
        } finally {
            sk.close();
        }
        result.put("files", files);
        result.put("completed", true);
        return result;
    }

    public static void main(String[] args) {
        Map<String, Object> result;
        try {
            result = execute(args);
        } catch (Exception failure) {
            result = new LinkedHashMap<>();
            result.put("schemaVersion", 1);
            result.put("completed", false);
            result.put("error", failure.toString());
            failure.printStackTrace(System.err);
        }
        System.out.println(new Gson().toJson(result));
        if (!Boolean.TRUE.equals(result.get("completed"))) System.exit(1);
    }
}
