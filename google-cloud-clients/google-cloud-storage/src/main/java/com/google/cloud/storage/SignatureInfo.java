/*
 * Copyright 2015 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.cloud.storage;

import static com.google.common.base.Preconditions.checkArgument;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.common.hash.Hashing;
import com.google.common.net.UrlEscapers;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

/**
 * Signature Info holds payload components of the string that requires signing.
 *
 * @see <a href=
 *     "https://cloud.google.com/storage/docs/access-control/signed-urls#string-components">
 *     Components</a>
 */
public class SignatureInfo {

  public static final char COMPONENT_SEPARATOR = '\n';
  public static final String GOOG4_RSA_SHA256 = "GOOG4-RSA-SHA256";
  public static final String SCOPE = "/auto/storage/goog4_request";

  private final HttpMethod httpVerb;
  private final String contentMd5;
  private final String contentType;
  private final long expiration;
  private final Map<String, String> canonicalizedExtensionHeaders;
  private final ListMultimap<String, String> canonicalizedQueryParams;
  private final URI canonicalizedResource;
  private final Storage.SignUrlOption.SignatureVersion signatureVersion;
  private final String accountEmail;
  private final long timestamp;

  private final String yearMonthDay;
  private final String exactDate;

  private SignatureInfo(Builder builder) {
    this.httpVerb = builder.httpVerb;
    this.contentMd5 = builder.contentMd5;
    this.contentType = builder.contentType;
    this.expiration = builder.expiration;
    this.canonicalizedResource = builder.canonicalizedResource;
    this.signatureVersion = builder.signatureVersion;
    this.accountEmail = builder.accountEmail;
    this.timestamp = builder.timestamp;

    ImmutableMap.Builder<String, String> headerBuilder =
        new ImmutableMap.Builder<String, String>().putAll(builder.canonicalizedExtensionHeaders);
    if (Storage.SignUrlOption.SignatureVersion.V4.equals(signatureVersion)
        && (!builder.canonicalizedExtensionHeaders.containsKey("host"))) {
      headerBuilder.put("host", "storage.googleapis.com");
    }
    canonicalizedExtensionHeaders = headerBuilder.build();

    canonicalizedQueryParams = ArrayListMultimap.create(builder.canonicalizedQueryParams);

    Date date = new Date(timestamp);

    SimpleDateFormat yearMonthDayFormat = new SimpleDateFormat("yyyyMMdd");
    SimpleDateFormat exactDateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");

    yearMonthDayFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    exactDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

    yearMonthDay = yearMonthDayFormat.format(date);
    exactDate = exactDateFormat.format(date);
  }

  /**
   * Constructs payload to be signed.
   *
   * @return payload to sign
   * @see <a href="https://cloud.google.com/storage/docs/access-control#Signed-URLs">Signed URLs</a>
   */
  public String constructUnsignedPayload() {
    // TODO reverse order when V4 becomes default
    if (Storage.SignUrlOption.SignatureVersion.V4.equals(signatureVersion)) {
      return constructV4UnsignedPayload();
    }
    return constructV2UnsignedPayload();
  }

  private String constructV2UnsignedPayload() {
    StringBuilder payload = new StringBuilder();

    payload.append(httpVerb.name()).append(COMPONENT_SEPARATOR);
    if (contentMd5 != null) {
      payload.append(contentMd5);
    }
    payload.append(COMPONENT_SEPARATOR);

    if (contentType != null) {
      payload.append(contentType);
    }
    payload.append(COMPONENT_SEPARATOR);
    payload.append(expiration).append(COMPONENT_SEPARATOR);

    if (canonicalizedExtensionHeaders.size() > 0) {
      payload.append(
          new CanonicalExtensionHeadersSerializer(Storage.SignUrlOption.SignatureVersion.V2)
              .serialize(canonicalizedExtensionHeaders));
    }

    payload.append(canonicalizedResource);

    return payload.toString();
  }

  private String constructV4UnsignedPayload() {
    StringBuilder payload = new StringBuilder();

    payload.append(GOOG4_RSA_SHA256).append(COMPONENT_SEPARATOR);
    payload.append(exactDate).append(COMPONENT_SEPARATOR);
    payload.append(yearMonthDay).append(SCOPE).append(COMPONENT_SEPARATOR);
    payload.append(constructV4CanonicalRequestHash());

    return payload.toString();
  }

  private String constructV4CanonicalRequestHash() {
    StringBuilder canonicalRequest = new StringBuilder();

    CanonicalExtensionHeadersSerializer serializer =
        new CanonicalExtensionHeadersSerializer(Storage.SignUrlOption.SignatureVersion.V4);

    canonicalRequest.append(httpVerb.name()).append(COMPONENT_SEPARATOR);
    canonicalRequest.append(canonicalizedResource).append(COMPONENT_SEPARATOR);
    canonicalRequest.append(constructV4QueryString()).append(COMPONENT_SEPARATOR);
    canonicalRequest
        .append(serializer.serialize(canonicalizedExtensionHeaders))
        .append(COMPONENT_SEPARATOR);
    canonicalRequest
        .append(serializer.serializeHeaderNames(canonicalizedExtensionHeaders))
        .append(COMPONENT_SEPARATOR);
    canonicalRequest.append("UNSIGNED-PAYLOAD");

    return Hashing.sha256()
        .hashString(canonicalRequest.toString(), StandardCharsets.UTF_8)
        .toString();
  }

  public String constructV4QueryString() {
    StringBuilder signedHeaders =
        new CanonicalExtensionHeadersSerializer(Storage.SignUrlOption.SignatureVersion.V4)
            .serializeHeaderNames(canonicalizedExtensionHeaders);

    // Remove any instances of well-known required headers that might have been supplied by the
    // caller. We'll calculate and populate them below.
    // Convert to (and check for the existence of) lowercase keys to prevent cases like a user
    // supplying "x-goog-algorithm", in order to prevent the resulting query string from containing
    // "x-goog-algorithm" and "X-Goog-Algorithm".
    Set<String> reservedKeySet =
        Sets.newHashSet(
            "x-goog-algorithm",
            "x-goog-credential",
            "x-goog-date",
            "x-goog-expires",
            "x-goog-signedheaders");
    ListMultimap<String, String> paramMap = ArrayListMultimap.create(canonicalizedQueryParams);
    // ListMultimap yields keys as a view collection; we can't remove from the collection while
    // iterating over it, so we use two passes - one to form a standalone collection of the keys
    // to remove, and one to remove all the entries at each key.
    Set<String> keysToRemove = new HashSet<String>();
    for (String key : paramMap.keySet()) {
      if (reservedKeySet.contains(key.toLowerCase())) {
        keysToRemove.add(key);
      }
    }
    for (String key : keysToRemove) {
      paramMap.removeAll(key);
    }

    paramMap.put("X-Goog-Algorithm", GOOG4_RSA_SHA256);
    paramMap.put(
        "X-Goog-Credential",
        UrlEscapers.urlFormParameterEscaper().escape(accountEmail + "/" + yearMonthDay + SCOPE));
    paramMap.put("X-Goog-Date", exactDate);
    paramMap.put("X-Goog-Expires", Long.toString(expiration));
    paramMap.put(
        "X-Goog-SignedHeaders",
        UrlEscapers.urlFormParameterEscaper().escape(signedHeaders.toString()));

    StringBuilder queryStringBuilder = new StringBuilder();
    // When forming the canonical query string, we need to be able to sort first by keys, then by
    // values for any key with multiple values. The ListMultimap lets us access and sort both of
    // those groupings easily.

    ArrayList<String> paramKeys = Lists.newArrayList(paramMap.keySet());
    // TODO(b/139499439): Remove this once the service-side validation issue is fixed.
    // There is currently a bug in the service side validation that orders params in the wrong
    // manner (case-insensitive alphabetical order, rather than case-sensitive) when constructing
    // the querystring to validate against. In the mean time, we use a custom comparator for our
    // map to order our params in the same way the service validator does.
    // Collections.sort(paramKeys);
    Collections.sort(
        paramKeys,
        new Comparator<String>() {
          public int compare(String o1, String o2) {
            return o1.toLowerCase().compareTo(o2.toLowerCase());
          }
        });
    for (String key : paramKeys) {
      List<String> valuesForCurrentKey = paramMap.get(key);
      if (valuesForCurrentKey.size() > 1) {
        // If there's more than 1 value for the given key, create a standalone list from the given
        // view collection and sort it.
        valuesForCurrentKey = Lists.newArrayList(valuesForCurrentKey);
        Collections.sort(valuesForCurrentKey);
      }
      for (String value : valuesForCurrentKey) {
        queryStringBuilder.append(key).append('=').append(value).append('&');
      }
    }
    // Remove trailing '&' from last-added param.
    if (queryStringBuilder.length() > 0) {
      queryStringBuilder.setLength(queryStringBuilder.length() - 1);
    }

    return queryStringBuilder.toString();
  }

  public HttpMethod getHttpVerb() {
    return httpVerb;
  }

  public String getContentMd5() {
    return contentMd5;
  }

  public String getContentType() {
    return contentType;
  }

  public long getExpiration() {
    return expiration;
  }

  public Map<String, String> getCanonicalizedExtensionHeaders() {
    return canonicalizedExtensionHeaders;
  }

  public ListMultimap<String, String> getCanonicalizedQueryParams() {
    return canonicalizedQueryParams;
  }

  public URI getCanonicalizedResource() {
    return canonicalizedResource;
  }

  public Storage.SignUrlOption.SignatureVersion getSignatureVersion() {
    return signatureVersion;
  }

  public long getTimestamp() {
    return timestamp;
  }

  public String getAccountEmail() {
    return accountEmail;
  }

  public static final class QueryParamPair {
    private String key;
    private String value;

    public QueryParamPair(String key, String value) {
      this.key = key;
      this.value = value;
    }

    public String getKey() {
      return key;
    }

    public String getValue() {
      return value;
    }
  }

  public static final class Builder {

    private final HttpMethod httpVerb;
    private String contentMd5;
    private String contentType;
    private final long expiration;
    private Map<String, String> canonicalizedExtensionHeaders;
    private ListMultimap<String, String> canonicalizedQueryParams;
    private final URI canonicalizedResource;
    private Storage.SignUrlOption.SignatureVersion signatureVersion;
    private String accountEmail;
    private long timestamp;

    /**
     * Constructs builder.
     *
     * @param httpVerb the HTTP method
     * @param expiration the EPOX expiration date
     * @param canonicalizedResource the resource URI
     * @throws IllegalArgumentException if required field is not provided.
     */
    public Builder(HttpMethod httpVerb, long expiration, URI canonicalizedResource) {
      this.httpVerb = httpVerb;
      this.expiration = expiration;
      this.canonicalizedResource = canonicalizedResource;
    }

    public Builder(SignatureInfo signatureInfo) {
      this.httpVerb = signatureInfo.httpVerb;
      this.contentMd5 = signatureInfo.contentMd5;
      this.contentType = signatureInfo.contentType;
      this.expiration = signatureInfo.expiration;
      this.canonicalizedExtensionHeaders = signatureInfo.canonicalizedExtensionHeaders;
      this.canonicalizedQueryParams = signatureInfo.canonicalizedQueryParams;
      this.canonicalizedResource = signatureInfo.canonicalizedResource;
      this.signatureVersion = signatureInfo.signatureVersion;
      this.accountEmail = signatureInfo.accountEmail;
      this.timestamp = signatureInfo.timestamp;
    }

    public Builder setContentMd5(String contentMd5) {
      this.contentMd5 = contentMd5;

      return this;
    }

    public Builder setContentType(String contentType) {
      this.contentType = contentType;

      return this;
    }

    public Builder setCanonicalizedExtensionHeaders(
        Map<String, String> canonicalizedExtensionHeaders) {
      this.canonicalizedExtensionHeaders = canonicalizedExtensionHeaders;

      return this;
    }

    public Builder setCanonicalizedQueryParams(
        ListMultimap<String, String> canonicalizedQueryParams) {
      this.canonicalizedQueryParams = canonicalizedQueryParams;

      return this;
    }

    public Builder setSignatureVersion(Storage.SignUrlOption.SignatureVersion signatureVersion) {
      this.signatureVersion = signatureVersion;

      return this;
    }

    public Builder setAccountEmail(String accountEmail) {
      this.accountEmail = accountEmail;

      return this;
    }

    public Builder setTimestamp(long timestamp) {
      this.timestamp = timestamp;

      return this;
    }

    /** Creates an {@code SignatureInfo} object from this builder. */
    public SignatureInfo build() {
      checkArgument(httpVerb != null, "Required HTTP method");
      checkArgument(canonicalizedResource != null, "Required canonicalized resource");
      checkArgument(expiration >= 0, "Expiration must be greater than or equal to zero");

      if (Storage.SignUrlOption.SignatureVersion.V4.equals(signatureVersion)) {
        checkArgument(accountEmail != null, "Account email required to use V4 signing");
        checkArgument(timestamp > 0, "Timestamp required to use V4 signing");
        checkArgument(
            expiration <= 604800, "Expiration can't be longer than 7 days to use V4 signing");
      }

      if (canonicalizedExtensionHeaders == null) {
        canonicalizedExtensionHeaders = new HashMap<>();
      }

      if (canonicalizedQueryParams == null) {
        canonicalizedQueryParams = ArrayListMultimap.create();
      }

      return new SignatureInfo(this);
    }
  }
}
