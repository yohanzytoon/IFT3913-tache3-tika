/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tika.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyStore;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;

import org.apache.tika.io.TemporaryResources;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.utils.XMLReaderUtils;

/**
 * Controlled assignment proofs. Enable explicitly with -Dtache3.demo=true.
 * The same probes must show secure behavior on main and unsafe behavior on
 * the educational branch (-Dtache3.expectVulnerable=true).
 */
@EnabledIfSystemProperty(named = "tache3.demo", matches = "true")
@Timeout(30)
public class Tache3SecurityProofTest {

    @TempDir
    Path directory;

    private boolean expectVulnerable() {
        return Boolean.getBoolean("tache3.expectVulnerable");
    }

    @Test
    public void externalEntityReadsOnlyOurTemporaryMarker() throws Exception {
        Path marker = directory.resolve("marker.txt");
        Files.writeString(marker, "TACHE3_LOCAL_MARKER", StandardCharsets.UTF_8);
        String xml = "<!DOCTYPE doc [<!ENTITY proof SYSTEM \"" + marker.toUri() +
                "\">]><doc>&proof;</doc>";
        // Test the public factory, without the separate protected builder's resolver.
        Document document = XMLReaderUtils.getDocumentBuilderFactory().newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        assertEquals(expectVulnerable() ? "TACHE3_LOCAL_MARKER" : "",
                document.getDocumentElement().getTextContent());
    }

    @Test
    public void temporaryDocumentPermissionsExposeOtherUsers() throws Exception {
        assumeTrue(Files.getFileStore(directory).supportsFileAttributeView("posix"));
        Path created;
        try (TemporaryResources resources = new TemporaryResources()) {
            resources.setTemporaryFileDirectory(directory);
            created = resources.createTempFile(".txt");
            Files.writeString(created, "TACHE3_SYNTHETIC_DOCUMENT", StandardCharsets.UTF_8);
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(created);
            assertEquals(expectVulnerable(), permissions.contains(PosixFilePermission.OTHERS_READ));
            assertEquals(expectVulnerable(), permissions.contains(PosixFilePermission.OTHERS_WRITE));
        }
        assertFalse(Files.exists(created), "The normal cleanup still occurs");
    }

    @Test
    public void httpsRejectsOrAcceptsOurUntrustedLoopbackCertificate() throws Exception {
        Path keyStoreFile = directory.resolve("loopback.p12");
        // This password protects an ephemeral test key, not a real credential.
        String password = "assignment-fixture-only";
        Path keytool = Path.of(System.getProperty("java.home"), "bin", "keytool");
        Process generator = new ProcessBuilder(keytool.toString(), "-genkeypair",
                "-alias", "loopback", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "1", "-dname", "CN=localhost", "-ext",
                "SAN=dns:localhost,ip:127.0.0.1", "-storetype", "PKCS12",
                "-keystore", keyStoreFile.toString(), "-storepass", password,
                "-keypass", password, "-noprompt")
                .redirectErrorStream(true).redirectOutput(directory.resolve("keytool.log").toFile())
                .start();
        try {
            assertTrue(generator.waitFor(20, TimeUnit.SECONDS), "Key generation timed out");
            assertEquals(0, generator.exitValue(), Files.readString(directory.resolve("keytool.log")));
        } finally {
            if (generator.isAlive()) {
                generator.destroyForcibly();
            }
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(keyStoreFile)) {
            keyStore.load(input, password.toCharArray());
        }
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(keyStore, password.toCharArray());
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(managers.getKeyManagers(), null, null);
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext));
        server.createContext("/document", exchange -> {
            byte[] response = "TACHE3_TLS_MARKER".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, response.length);
            try (var output = exchange.getResponseBody()) {
                output.write(response);
            }
        });
        server.start();
        try {
            URI uri = URI.create("https://127.0.0.1:" + server.getAddress().getPort() + "/document");
            if (expectVulnerable()) {
                try (TikaInputStream stream = TikaInputStream.get(uri.toURL())) {
                    assertEquals("TACHE3_TLS_MARKER", new String(stream.readAllBytes(), StandardCharsets.UTF_8));
                }
            } else {
                assertThrows(IOException.class, () -> {
                    try (TikaInputStream stream = TikaInputStream.get(uri.toURL())) {
                        stream.readAllBytes();
                    }
                });
            }
        } finally {
            server.stop(0);
        }
    }
}
