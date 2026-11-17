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
package org.apache.tika.serialization;


import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

import org.apache.tika.metadata.Metadata;
import org.apache.tika.serialization.serdes.MetadataSerializer;

public class JsonMetadata {

    static volatile boolean PRETTY_PRINT = false;

    /**
     * Default stream read constraints for metadata serialization.
     */
    private static final StreamReadConstraints DEFAULT_CONSTRAINTS = StreamReadConstraints
            .builder()
            .maxNestingDepth(10)
            .maxStringLength(20_000_000)
            .maxNumberLength(500)
            .build();

    private static volatile StreamReadConstraints streamReadConstraints = DEFAULT_CONSTRAINTS;
    private static volatile ObjectMapper OBJECT_MAPPER;
    private static volatile ObjectMapper PRETTY_SERIALIZER;

    static {
        rebuildObjectMappers();
    }

    private static void rebuildObjectMappers() {
        JsonFactory factory = new JsonFactory();
        factory.setStreamReadConstraints(streamReadConstraints);

        // Use TikaModule which includes Metadata serializers
        ObjectMapper mapper = new ObjectMapper(factory);
        mapper.registerModule(new TikaModule());
        OBJECT_MAPPER = mapper;

        // Pretty printer needs custom serializer with sort flag
        ObjectMapper prettyMapper = new ObjectMapper(factory);
        SimpleModule prettySerializerModule = new SimpleModule();
        prettySerializerModule.addSerializer(Metadata.class, new MetadataSerializer(true));
        prettyMapper.registerModule(prettySerializerModule);
        PRETTY_SERIALIZER = prettyMapper;
    }

    /**
     * Sets the stream read constraints for JSON parsing of metadata.
     * This affects all subsequent calls to {@link #fromJson(Reader)}.
     * <p>
     * Typically called by TikaLoader during initialization based on the
     * "metadata-list" configuration section.
     *
     * @param constraints the constraints to use
     */
    public static synchronized void setStreamReadConstraints(StreamReadConstraints constraints) {
        streamReadConstraints = constraints;
        rebuildObjectMappers();
    }

    /**
     * Gets the current stream read constraints.
     *
     * @return the current constraints
     */
    public static StreamReadConstraints getStreamReadConstraints() {
        return streamReadConstraints;
    }

    /**
     * Serializes a Metadata object to Json.  This does not flush or close the writer.
     *
     * @param metadata metadata to write
     * @param writer   writer
     * @throws java.io.IOException if there is an IOException during writing
     */
    public static void toJson(Metadata metadata, Writer writer) throws IOException {
        if (PRETTY_PRINT) {
            PRETTY_SERIALIZER
                    .writerWithDefaultPrettyPrinter()
                    .writeValue(writer, metadata);
        } else {
            OBJECT_MAPPER.writeValue(writer, metadata);
        }
    }

    /**
     * Read metadata from reader. This does not close the reader.
     *
     * @param reader reader to read from
     * @return Metadata or null if reader is null
     * @throws IOException in case of parse failure or IO failure with Reader
     */
    public static Metadata fromJson(Reader reader) throws IOException {
        if (reader == null) {
            return null;
        }
        return OBJECT_MAPPER.readValue(reader, Metadata.class);
    }

    /**
     * Read metadata from a byte stream. Metadata written by older clients with
     * Java serialization is still accepted; any other content is read as UTF-8 JSON.
     * This does not close the stream.
     *
     * @param inputStream stream to read from
     * @return Metadata or null if the stream is null
     * @throws IOException in case of parse failure or IO failure with the stream
     */
    public static Metadata fromStream(InputStream inputStream) throws IOException {
        if (inputStream == null) {
            return null;
        }
        BufferedInputStream in = new BufferedInputStream(inputStream);
        in.mark(2);
        int first = in.read();
        int second = in.read();
        in.reset();
        if (first == 0xAC && second == 0xED) {
            ObjectInputStream objectInputStream = new ObjectInputStream(in);
            try {
                return (Metadata) objectInputStream.readObject();
            } catch (ClassNotFoundException e) {
                throw new IOException(e);
            }
        }
        return fromJson(new InputStreamReader(in, StandardCharsets.UTF_8));
    }

    public static void setPrettyPrinting(boolean prettyPrint) {
        PRETTY_PRINT = prettyPrint;
    }
}
