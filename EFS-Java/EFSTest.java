import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
class EFSTest {

    @Test
    void test1() {
        var efs = new EFS();
        try {
            efs.create("file.1", "kali", "1qazxsw2");
            var username = efs.findUser("file.1");
            assertEquals("kali", username);
            var len = efs.length("file.1", "1qazxsw2");
            assertEquals(0, len);
            assertTrue(efs.checkIntegrity("file.1", "1qazxsw2"));
        } catch (Exception e) {
            fail();
        }
    }

    @Test
    void test2() {
        var efs = new EFS();
        try {
            var filename = "file.2";
            var username = "kali";
            var password = "1qazxsw2";
            efs.create(filename, username, password);
            assertEquals(username, efs.findUser(filename));
            assertEquals(0, efs.length(filename, password));

            var metaFile = new File(filename, "0");
            var content = efs.readFromFile(metaFile);
            content[243] = (byte)~content[243];
            efs.saveToFile(content, metaFile);

            assertFalse(efs.checkIntegrity(filename, password));
        } catch (PasswordIncorrectException ignored) {
        } catch (Exception e) {
            fail();
        }
    }

    @Test
    void test4() {
        var efs = new EFS();
        try {
            var filename = "file.3";
            var username = "kali";
            var password = "1qazxsw2";
            efs.create(filename, username, password);
            assertTrue(efs.checkIntegrity(filename, password));

            var message = "This a message to test read and write operation for simple behaviour";
            efs.write(filename, 0, message.getBytes(StandardCharsets.UTF_8), password);
            var readMsg = efs.read(filename, 0, message.length(), password);
            assertEquals(message, new String(readMsg, StandardCharsets.UTF_8));
            assertTrue(efs.checkIntegrity(filename, password));

            var partMsg = efs.read(filename, 52, 16, password);
            assertEquals("simple behaviour", new String(partMsg, StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail();
        }
    }

    @Test
    void test5() {
        var efs = new EFS();
        try {
            var filename = "file.4";
            var username = "kali";
            var password = "1qazxsw2";
            efs.create(filename, username, password);

            var message = """
                    In a traditional file system, files are usually stored on disks unencrypted.
                    When the disks are stolen by someone, contents of those files can be easily recovered by the \
                    malicious people.
                    Encrypted File System (EFS) is developed to prevent such leakages.
                    In an EFS, files on disks are all encrypted, nobody can decrypt the files without knowing the \
                    required secret.
                    Therefore, even if a EFS disk is stolen, or if otherwise an adversary can read the file stored on \
                    the disk, its files are kept confidential.
                    EFS has been implemented in a number of operating systems, such as Solaris, Windows NT, and Linux.
                    In this project, you are asked to implement a simulated version of EFS in Java.
                    More specifically, you will need to implement several library functions, which simulates the \
                    functionalities of EFS.
                    Please commit your changes relatively frequently so that we can see your work clearly. \
                    Do not forget to push changes to the remote repository in Github!""";
            efs.write(filename, 0, message.getBytes(StandardCharsets.UTF_8), password);
            var readMsg = efs.read(filename, 0, message.length(), password);
            assertEquals(message, new String(readMsg, StandardCharsets.UTF_8));
            assertTrue(efs.checkIntegrity(filename, password));
        } catch (Exception e) {
            fail();
        }
    }
}
