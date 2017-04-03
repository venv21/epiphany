/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 *  Copyright © 2016 Gabriel Ivascu <ivascu.gabriel59@gmail.com>
 *
 *  This file is part of Epiphany.
 *
 *  Epiphany is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Epiphany is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Epiphany.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include "ephy-sync-crypto.h"

#include "ephy-sync-utils.h"

#include <glib/gstdio.h>
#include <inttypes.h>
#include <libsoup/soup.h>
#include <nettle/cbc.h>
#include <nettle/aes.h>
#include <string.h>

#define HAWK_VERSION  1
#define NONCE_LEN     6

static const char hex_digits[] = "0123456789abcdef";

SyncCryptoHawkOptions *
ephy_sync_crypto_hawk_options_new (const char *app,
                                   const char *dlg,
                                   const char *ext,
                                   const char *content_type,
                                   const char *hash,
                                   const char *local_time_offset,
                                   const char *nonce,
                                   const char *payload,
                                   const char *timestamp)
{
  SyncCryptoHawkOptions *options;

  options = g_slice_new (SyncCryptoHawkOptions);
  options->app = g_strdup (app);
  options->dlg = g_strdup (dlg);
  options->ext = g_strdup (ext);
  options->content_type = g_strdup (content_type);
  options->hash = g_strdup (hash);
  options->local_time_offset = g_strdup (local_time_offset);
  options->nonce = g_strdup (nonce);
  options->payload = g_strdup (payload);
  options->timestamp = g_strdup (timestamp);

  return options;
}

void
ephy_sync_crypto_hawk_options_free (SyncCryptoHawkOptions *options)
{
  g_return_if_fail (options);

  g_free (options->app);
  g_free (options->dlg);
  g_free (options->ext);
  g_free (options->content_type);
  g_free (options->hash);
  g_free (options->local_time_offset);
  g_free (options->nonce);
  g_free (options->payload);
  g_free (options->timestamp);

  g_slice_free (SyncCryptoHawkOptions, options);
}

static SyncCryptoHawkArtifacts *
ephy_sync_crypto_hawk_artifacts_new (const char *app,
                                     const char *dlg,
                                     const char *ext,
                                     const char *hash,
                                     const char *host,
                                     const char *method,
                                     const char *nonce,
                                     guint       port,
                                     const char *resource,
                                     gint64      ts)
{
  SyncCryptoHawkArtifacts *artifacts;

  artifacts = g_slice_new (SyncCryptoHawkArtifacts);
  artifacts->app = g_strdup (app);
  artifacts->dlg = g_strdup (dlg);
  artifacts->ext = g_strdup (ext);
  artifacts->hash = g_strdup (hash);
  artifacts->host = g_strdup (host);
  artifacts->method = g_strdup (method);
  artifacts->nonce = g_strdup (nonce);
  artifacts->port = g_strdup_printf ("%u", port);
  artifacts->resource = g_strdup (resource);
  artifacts->ts = g_strdup_printf ("%" PRId64, ts);

  return artifacts;
}

static void
ephy_sync_crypto_hawk_artifacts_free (SyncCryptoHawkArtifacts *artifacts)
{
  g_assert (artifacts);

  g_free (artifacts->app);
  g_free (artifacts->dlg);
  g_free (artifacts->ext);
  g_free (artifacts->hash);
  g_free (artifacts->host);
  g_free (artifacts->method);
  g_free (artifacts->nonce);
  g_free (artifacts->port);
  g_free (artifacts->resource);
  g_free (artifacts->ts);

  g_slice_free (SyncCryptoHawkArtifacts, artifacts);
}

static SyncCryptoHawkHeader *
ephy_sync_crypto_hawk_header_new (char                    *header,
                                  SyncCryptoHawkArtifacts *artifacts)
{
  SyncCryptoHawkHeader *hheader;

  hheader = g_slice_new (SyncCryptoHawkHeader);
  hheader->header = header;
  hheader->artifacts = artifacts;

  return hheader;
}

void
ephy_sync_crypto_hawk_header_free (SyncCryptoHawkHeader *hheader)
{
  g_return_if_fail (hheader);

  g_free (hheader->header);
  ephy_sync_crypto_hawk_artifacts_free (hheader->artifacts);

  g_slice_free (SyncCryptoHawkHeader, hheader);
}

static SyncCryptoRSAKeyPair *
ephy_sync_crypto_rsa_key_pair_new (struct rsa_public_key  public,
                                   struct rsa_private_key private)
{
  SyncCryptoRSAKeyPair *keypair;

  keypair = g_slice_new (SyncCryptoRSAKeyPair);
  keypair->public = public;
  keypair->private = private;

  return keypair;
}

void
ephy_sync_crypto_rsa_key_pair_free (SyncCryptoRSAKeyPair *keypair)
{
  g_return_if_fail (keypair);

  rsa_public_key_clear (&keypair->public);
  rsa_private_key_clear (&keypair->private);

  g_slice_free (SyncCryptoRSAKeyPair, keypair);
}

static char *
ephy_sync_crypto_kw (const char *name)
{
  g_assert (name);

  /* Concatenate the given name to the Mozilla prefix.
   * See https://raw.githubusercontent.com/wiki/mozilla/fxa-auth-server/images/onepw-create.png
   */
  return g_strconcat ("identity.mozilla.com/picl/v1/", name, NULL);
}

static guint8 *
ephy_sync_crypto_xor (guint8 *a,
                      guint8 *b,
                      gsize   length)
{
  guint8 *xored;

  g_assert (a);
  g_assert (b);

  xored = g_malloc (length);
  for (gsize i = 0; i < length; i++)
    xored[i] = a[i] ^ b[i];

  return xored;
}

static gboolean
ephy_sync_crypto_equals (guint8 *a,
                         guint8 *b,
                         gsize   length)
{
  g_assert (a);
  g_assert (b);

  for (gsize i = 0; i < length; i++)
    if (a[i] != b[i])
      return FALSE;

  return TRUE;
}

static char *
ephy_sync_crypto_normalize_string (const char              *type,
                                   SyncCryptoHawkArtifacts *artifacts)
{
  char *host;
  char *info;
  char *method;
  char *n_ext = NULL;
  char *normalized;
  char *tmp;

  g_assert (type);
  g_assert (artifacts);

  info = g_strdup_printf ("hawk.%d.%s", HAWK_VERSION, type);
  method = g_ascii_strup (artifacts->method, -1);
  host = g_ascii_strdown (artifacts->host, -1);

  normalized = g_strjoin ("\n",
                          info, artifacts->ts, artifacts->nonce,
                          method, artifacts->resource, host,
                          artifacts->port, artifacts->hash ? artifacts->hash : "",
                          NULL);

  if (artifacts->ext && strlen (artifacts->ext) > 0) {
    tmp = ephy_sync_utils_find_and_replace (artifacts->ext, "\\", "\\\\");
    n_ext = ephy_sync_utils_find_and_replace (tmp, "\n", "\\n");
    g_free (tmp);
  }

  tmp = normalized;
  normalized = g_strconcat (normalized, "\n",
                            n_ext ? n_ext : "", "\n",
                            artifacts->app ? artifacts->app : "",
                            artifacts->app ? "\n" : "",
                            artifacts->app && artifacts->dlg ? artifacts->dlg : "",
                            artifacts->app && artifacts->dlg ? "\n" : "",
                            NULL);

  g_free (host);
  g_free (info);
  g_free (method);
  g_free (n_ext);
  g_free (tmp);

  return normalized;
}

static char *
ephy_sync_crypto_parse_content_type (const char *content_type)
{
  char **tokens;
  char *retval;

  g_assert (content_type);

  tokens = g_strsplit (content_type, ";", -1);
  retval = g_ascii_strdown (g_strstrip (tokens[0]), -1);
  g_strfreev (tokens);

  return retval;
}

static char *
ephy_sync_crypto_calculate_payload_hash (const char *payload,
                                         const char *content_type)
{
  guint8 *digest;
  char *digest_hex;
  char *content;
  char *update;
  char *hash;

  g_assert (payload);
  g_assert (content_type);

  content = ephy_sync_crypto_parse_content_type (content_type);
  update = g_strdup_printf ("hawk.%d.payload\n%s\n%s\n",
                            HAWK_VERSION, content, payload);

  digest_hex = g_compute_checksum_for_string (G_CHECKSUM_SHA256, update, -1);
  digest = ephy_sync_crypto_decode_hex (digest_hex);
  hash = g_base64_encode (digest, g_checksum_type_get_length (G_CHECKSUM_SHA256));

  g_free (content);
  g_free (update);
  g_free (digest_hex);
  g_free (digest);

  return hash;
}

static char *
ephy_sync_crypto_calculate_mac (const char              *type,
                                guint8                  *key,
                                gsize                    key_len,
                                SyncCryptoHawkArtifacts *artifacts)
{
  guint8 *digest;
  char *digest_hex;
  char *normalized;
  char *mac;

  g_assert (type);
  g_assert (key);
  g_assert (artifacts);

  /* Serialize the mac type and artifacts into a HAWK string. */
  normalized = ephy_sync_crypto_normalize_string (type, artifacts);
  digest_hex = g_compute_hmac_for_string (G_CHECKSUM_SHA256, key, key_len, normalized, -1);
  digest = ephy_sync_crypto_decode_hex (digest_hex);
  mac = g_base64_encode (digest, g_checksum_type_get_length (G_CHECKSUM_SHA256));

  g_free (normalized);
  g_free (digest_hex);
  g_free (digest);

  return mac;
}

static char *
ephy_sync_crypto_append_to_header (char       *header,
                                   const char *name,
                                   char       *value)
{
  char *new_header;
  char *tmp;

  g_assert (header);
  g_assert (name);
  g_assert (value);

  tmp = header;
  new_header = g_strconcat (header, ", ", name, "=\"", value, "\"", NULL);
  g_free (tmp);

  return new_header;
}

static void
ephy_sync_crypto_hkdf (guint8 *in,
                       gsize   in_len,
                       guint8 *salt,
                       gsize   salt_len,
                       guint8 *info,
                       gsize   info_len,
                       guint8 *out,
                       gsize   out_len)
{
  char *prk_hex;
  char *tmp_hex;
  guint8 *tmp;
  guint8 *prk;
  guint8 *out_full;
  guint8 *data;
  guint8 counter;
  gsize hash_len;
  gsize data_len;
  gsize n;

  g_assert (in);
  g_assert (info);
  g_assert (out);

  hash_len = g_checksum_type_get_length (G_CHECKSUM_SHA256);
  g_assert (out_len <= hash_len * 255);

  /* Implementation of the HMAC-based Extract-and-Expand Key Derivation Function.
   * See https://tools.ietf.org/html/rfc5869 */

  /* If salt value was not provided, use an array of hash_len zeros. */
  if (!salt) {
    salt = g_malloc0 (hash_len);
    salt_len = hash_len;
  }

  /* Step 1: Extract */
  prk_hex = g_compute_hmac_for_data (G_CHECKSUM_SHA256, salt, salt_len, in, in_len);
  prk = ephy_sync_crypto_decode_hex (prk_hex);

  /* Step 2: Expand */
  counter = 1;
  n = (out_len + hash_len - 1) / hash_len;
  out_full = g_malloc (n * hash_len);

  for (gsize i = 0; i < n; i++, counter++) {
    if (i == 0) {
      data = ephy_sync_utils_concatenate_bytes (info, info_len, &counter, 1, NULL);
      data_len = info_len + 1;
    } else {
      data = ephy_sync_utils_concatenate_bytes (out_full + (i - 1) * hash_len, hash_len,
                                                info, info_len, &counter, 1,
                                                NULL);
      data_len = hash_len + info_len + 1;
    }

    tmp_hex = g_compute_hmac_for_data (G_CHECKSUM_SHA256, prk, hash_len, data, data_len);
    tmp = ephy_sync_crypto_decode_hex (tmp_hex);
    memcpy (out_full + i * hash_len, tmp, hash_len);

    g_free (data);
    g_free (tmp);
    g_free (tmp_hex);
  }

  memcpy (out, out_full, out_len);

  g_free (prk_hex);
  g_free (salt);
  g_free (prk);
  g_free (out_full);
}

static void
ephy_sync_crypto_b64_to_b64_urlsafe (char *text)
{
  g_assert (text);

  /* Replace '+' with '-' and '/' with '_' */
  g_strcanon (text, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=/", '-');
  g_strcanon (text, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=-", '_');
}

static void
ephy_sync_crypto_b64_urlsafe_to_b64 (char *text)
{
  g_assert (text);

  /* Replace '-' with '+' and '_' with '/' */
  g_strcanon (text, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=_", '+');
  g_strcanon (text, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=+", '/');
}

static guint8 *
ephy_sync_crypto_pad (const char *text,
                      gsize       block_len,
                      gsize      *out_len)
{
  guint8 *out;
  gsize text_len = strlen (text);

  g_assert (text);
  g_assert (out_len);

  if (text_len % block_len == 0)
    *out_len = text_len;
  else
    *out_len = text_len + block_len - text_len % block_len;

  out = g_malloc (*out_len);

  if (text_len % block_len != 0)
    memset (out, block_len - text_len % block_len, *out_len);

  memcpy (out, text, text_len);

  return out;
}

static guint8 *
ephy_sync_crypto_aes_256_encrypt (const char   *text,
                                  const guint8 *key,
                                  const guint8 *iv,
                                  gsize        *out_len)
{
  guint8 *padded;
  guint8 *encrypted;
  gsize padded_len;
  struct CBC_CTX(struct aes256_ctx, AES_BLOCK_SIZE) ctx;

  g_return_val_if_fail (text, NULL);
  g_return_val_if_fail (key, NULL);
  g_return_val_if_fail (iv, NULL);
  g_return_val_if_fail (out_len, NULL);

  padded = ephy_sync_crypto_pad (text, AES_BLOCK_SIZE, &padded_len);
  encrypted = g_malloc (padded_len);

  aes256_set_encrypt_key(&ctx.ctx, key);
  CBC_SET_IV(&ctx, iv);
  CBC_ENCRYPT(&ctx, aes256_encrypt, padded_len, encrypted, padded);

  *out_len = padded_len;
  g_free (padded);

  return encrypted;
}

static char *
ephy_sync_crypto_unpad (const guint8 *data,
                        gsize         data_len,
                        gsize         block_len)
{
  char *out;
  gsize out_len;
  gsize padding = data[data_len - 1];

  g_assert (data);

  if (padding >= 1 && padding <= block_len - 1)
    out_len = data_len - padding;
  else
    out_len = data_len;

  out = g_malloc0 (out_len + 1);
  memcpy (out, data, out_len);

  return out;
}

static char *
ephy_sync_crypto_aes_256_decrypt (const guint8 *data,
                                  gsize         data_len,
                                  const guint8 *key,
                                  const guint8 *iv)
{
  guint8 *decrypted;
  char *unpadded;
  struct CBC_CTX(struct aes256_ctx, AES_BLOCK_SIZE) ctx;

  g_return_val_if_fail (data, NULL);
  g_return_val_if_fail (key, NULL);
  g_return_val_if_fail (iv, NULL);

  decrypted = g_malloc (data_len);

  aes256_set_decrypt_key (&ctx.ctx, key);
  CBC_SET_IV (&ctx, iv);
  CBC_DECRYPT (&ctx, aes256_decrypt, data_len, decrypted, data);

  unpadded = ephy_sync_crypto_unpad (decrypted, data_len, AES_BLOCK_SIZE);
  g_free (decrypted);

  return unpadded;
}

void
ephy_sync_crypto_process_key_fetch_token (const char  *keyFetchToken,
                                          guint8     **tokenID,
                                          guint8     **reqHMACkey,
                                          guint8     **respHMACkey,
                                          guint8     **respXORkey)
{
  guint8 *kft;
  guint8 *out1;
  guint8 *out2;
  guint8 *keyRequestKey;
  char *info_kft;
  char *info_keys;

  g_return_if_fail (keyFetchToken);
  g_return_if_fail (tokenID);
  g_return_if_fail (reqHMACkey);
  g_return_if_fail (respHMACkey);
  g_return_if_fail (respXORkey);

  kft = ephy_sync_crypto_decode_hex (keyFetchToken);
  info_kft = ephy_sync_crypto_kw ("keyFetchToken");
  info_keys = ephy_sync_crypto_kw ("account/keys");
  out1 = g_malloc (3 * EPHY_SYNC_TOKEN_LENGTH);
  out2 = g_malloc (3 * EPHY_SYNC_TOKEN_LENGTH);

  /* Use the keyFetchToken to derive tokenID, reqHMACkey and keyRequestKey. */
  ephy_sync_crypto_hkdf (kft, EPHY_SYNC_TOKEN_LENGTH,
                         NULL, 0,
                         (guint8 *)info_kft, strlen (info_kft),
                         out1, 3 * EPHY_SYNC_TOKEN_LENGTH);

  *tokenID = g_malloc (EPHY_SYNC_TOKEN_LENGTH);
  *reqHMACkey = g_malloc (EPHY_SYNC_TOKEN_LENGTH);
  keyRequestKey = g_malloc (EPHY_SYNC_TOKEN_LENGTH);
  memcpy (*tokenID, out1, EPHY_SYNC_TOKEN_LENGTH);
  memcpy (*reqHMACkey, out1 + EPHY_SYNC_TOKEN_LENGTH, EPHY_SYNC_TOKEN_LENGTH);
  memcpy (keyRequestKey, out1 + 2 * EPHY_SYNC_TOKEN_LENGTH, EPHY_SYNC_TOKEN_LENGTH);

  /* Use the keyRequestKey to derive respHMACkey and respXORkey. */
  ephy_sync_crypto_hkdf (keyRequestKey, EPHY_SYNC_TOKEN_LENGTH,
                         NULL, 0,
                         (guint8 *)info_keys, strlen (info_keys),
                         out2, 3 * EPHY_SYNC_TOKEN_LENGTH);

  *respHMACkey = g_malloc (EPHY_SYNC_TOKEN_LENGTH);
  *respXORkey = g_malloc (2 * EPHY_SYNC_TOKEN_LENGTH);
  memcpy (*respHMACkey, out2, EPHY_SYNC_TOKEN_LENGTH);
  memcpy (*respXORkey, out2 + EPHY_SYNC_TOKEN_LENGTH, 2 * EPHY_SYNC_TOKEN_LENGTH);

  g_free (kft);
  g_free (out1);
  g_free (out2);
  g_free (info_kft);
  g_free (info_keys);
  g_free (keyRequestKey);
}

void
ephy_sync_crypto_process_session_token (const char  *sessionToken,
                                        guint8     **tokenID,
                                        guint8     **reqHMACkey,
                                        guint8     **requestKey)
{
  guint8 *st;
  guint8 *out;
  char *info;

  g_return_if_fail (sessionToken);
  g_return_if_fail (tokenID);
  g_return_if_fail (reqHMACkey);
  g_return_if_fail (requestKey);

  st = ephy_sync_crypto_decode_hex (sessionToken);
  info = ephy_sync_crypto_kw ("sessionToken");
  out = g_malloc (3 * EPHY_SYNC_TOKEN_LENGTH);

  /* Use the sessionToken to derive tokenID, reqHMACkey and requestKey. */
  ephy_sync_crypto_hkdf (st, EPHY_SYNC_TOKEN_LENGTH,
                         NULL, 0,
                         (guint8 *)info, strlen (info),
                         out, 3 * EPHY_SYNC_TOKEN_LENGTH);

  *tokenID = g_malloc (EPHY_SYNC_TOKEN_LENGTH);
  *reqHMACkey = g_malloc (EPHY_SYNC_TOKEN_LENGTH);
  *requestKey = g_malloc (EPHY_SYNC_TOKEN_LENGTH);
  memcpy (*tokenID, out, EPHY_SYNC_TOKEN_LENGTH);
  memcpy (*reqHMACkey, out + EPHY_SYNC_TOKEN_LENGTH, EPHY_SYNC_TOKEN_LENGTH);
  memcpy (*requestKey, out + 2 * EPHY_SYNC_TOKEN_LENGTH, EPHY_SYNC_TOKEN_LENGTH);

  g_free (st);
  g_free (out);
  g_free (info);
}

void
ephy_sync_crypto_compute_sync_keys (const char  *bundle,
                                    guint8      *respHMACkey,
                                    guint8      *respXORkey,
                                    guint8      *unwrapBKey,
                                    guint8     **kA,
                                    guint8     **kB)
{
  guint8 *bdl;
  guint8 *ciphertext;
  guint8 *respMAC;
  guint8 *respMAC2;
  guint8 *xored;
  guint8 *wrapKB;
  char *respMAC2_hex;

  g_return_if_fail (bundle);
  g_return_if_fail (respHMACkey);
  g_return_if_fail (respXORkey);
  g_return_if_fail (unwrapBKey);
  g_return_if_fail (kA);
  g_return_if_fail (kB);

  bdl = ephy_sync_crypto_decode_hex (bundle);
  ciphertext = g_malloc (2 * EPHY_SYNC_TOKEN_LENGTH);
  respMAC = g_malloc (EPHY_SYNC_TOKEN_LENGTH);
  wrapKB = g_malloc (EPHY_SYNC_TOKEN_LENGTH);
  *kA = g_malloc (EPHY_SYNC_TOKEN_LENGTH);

  /* Compute the MAC and compare it to the expected value. */
  memcpy (ciphertext, bdl, 2 * EPHY_SYNC_TOKEN_LENGTH);
  memcpy (respMAC, bdl + 2 * EPHY_SYNC_TOKEN_LENGTH, EPHY_SYNC_TOKEN_LENGTH);
  respMAC2_hex = g_compute_hmac_for_data (G_CHECKSUM_SHA256,
                                          respHMACkey, EPHY_SYNC_TOKEN_LENGTH,
                                          ciphertext, 2 * EPHY_SYNC_TOKEN_LENGTH);
  respMAC2 = ephy_sync_crypto_decode_hex (respMAC2_hex);
  g_assert (ephy_sync_crypto_equals (respMAC, respMAC2, EPHY_SYNC_TOKEN_LENGTH));

  /* XOR the extracted ciphertext with the respXORkey, then split in into the
   * separate kA and wrap(kB) values. */
  xored = ephy_sync_crypto_xor (ciphertext, respXORkey, 2 * EPHY_SYNC_TOKEN_LENGTH);
  memcpy (*kA, xored, EPHY_SYNC_TOKEN_LENGTH);
  memcpy (wrapKB, xored + EPHY_SYNC_TOKEN_LENGTH, EPHY_SYNC_TOKEN_LENGTH);

  /* Finally, XOR wrap(kB) with unwrapBKey to obtain kB. There is no MAC on wrap(kB). */
  *kB = ephy_sync_crypto_xor (unwrapBKey, wrapKB, EPHY_SYNC_TOKEN_LENGTH);

  g_free (bdl);
  g_free (ciphertext);
  g_free (respMAC);
  g_free (respMAC2);
  g_free (xored);
  g_free (wrapKB);
  g_free (respMAC2_hex);
}

void
ephy_sync_crypto_derive_master_keys (const guint8  *kB,
                                     guint8       **aes_key,
                                     guint8       **hmac_key)
{
  guint8 *salt;
  guint8 *prk;
  guint8 *tmp;
  char *prk_hex;
  char *aes_key_hex;
  char *hmac_key_hex;
  const char *info = "identity.mozilla.com/picl/v1/oldsync";

  g_return_if_fail (kB);
  g_return_if_fail (aes_key);
  g_return_if_fail (hmac_key);

  /* Perform a two step HKDF with an all-zeros salt.
   * T(1) will represent the AES key, T(2) will represent the HMAC key. */

  salt = g_malloc0 (EPHY_SYNC_TOKEN_LENGTH);
  prk_hex = g_compute_hmac_for_data (G_CHECKSUM_SHA256,
                                     salt, EPHY_SYNC_TOKEN_LENGTH,
                                     kB, EPHY_SYNC_TOKEN_LENGTH);
  prk = ephy_sync_crypto_decode_hex (prk_hex);
  tmp = ephy_sync_utils_concatenate_bytes ((guint8 *)info, strlen (info),
                                           "\x01", 1,
                                           NULL);
  aes_key_hex = g_compute_hmac_for_data (G_CHECKSUM_SHA256,
                                         prk, EPHY_SYNC_TOKEN_LENGTH,
                                         tmp, strlen (info) + 1);
  *aes_key = ephy_sync_crypto_decode_hex (aes_key_hex);
  g_free (tmp);
  tmp = ephy_sync_utils_concatenate_bytes (*aes_key, EPHY_SYNC_TOKEN_LENGTH,
                                           (guint8 *)info, strlen (info),
                                           "\x02", 1,
                                           NULL);
  hmac_key_hex = g_compute_hmac_for_data (G_CHECKSUM_SHA256,
                                          prk, EPHY_SYNC_TOKEN_LENGTH,
                                          tmp, EPHY_SYNC_TOKEN_LENGTH + strlen (info) + 1);
  *hmac_key = ephy_sync_crypto_decode_hex (hmac_key_hex);

  g_free (salt);
  g_free (prk_hex);
  g_free (prk);
  g_free (tmp);
  g_free (aes_key_hex);
  g_free (hmac_key_hex);
}

gboolean
ephy_sync_crypto_sha256_hmac_is_valid (const char   *text,
                                       const guint8 *key,
                                       const char   *expected)
{
  char *hmac;
  gboolean retval;

  g_return_val_if_fail (text, FALSE);
  g_return_val_if_fail (key, FALSE);
  g_return_val_if_fail (expected, FALSE);

  /* SHA256 expects a 32 bytes key. */
  hmac = g_compute_hmac_for_string (G_CHECKSUM_SHA256, key, 32, text, -1);
  retval = g_strcmp0 (hmac, expected) == 0;
  g_free (hmac);

  return retval;
}

char *
ephy_sync_crypto_decrypt_record (const char   *ciphertext_b64,
                                 const char   *iv_b64,
                                 const guint8 *aes_key)
{
  char *decrypted;
  guint8 *ciphertext;
  guint8 *iv;
  gsize ciphertext_len;
  gsize iv_len;

  g_return_val_if_fail (ciphertext_b64, NULL);
  g_return_val_if_fail (iv_b64, NULL);
  g_return_val_if_fail (aes_key, NULL);

  ciphertext = g_base64_decode (ciphertext_b64, &ciphertext_len);
  iv = g_base64_decode (iv_b64, &iv_len);
  decrypted = ephy_sync_crypto_aes_256_decrypt (ciphertext, ciphertext_len, aes_key, iv);

  g_free (ciphertext);
  g_free (iv);

  return decrypted;
}

SyncCryptoHawkHeader *
ephy_sync_crypto_compute_hawk_header (const char            *url,
                                      const char            *method,
                                      const char            *id,
                                      guint8                *key,
                                      gsize                  key_len,
                                      SyncCryptoHawkOptions *options)
{
  SyncCryptoHawkArtifacts *artifacts;
  SoupURI *uri;
  char *resource;
  char *hash;
  char *header;
  char *mac;
  char *nonce;
  char *payload;
  char *timestamp;
  gint64 ts;

  g_return_val_if_fail (url, NULL);
  g_return_val_if_fail (method, NULL);
  g_return_val_if_fail (id, NULL);
  g_return_val_if_fail (key, NULL);

  ts = ephy_sync_utils_current_time_seconds ();
  hash = options ? g_strdup (options->hash) : NULL;
  payload = options ? options->payload : NULL;
  timestamp = options ? options->timestamp : NULL;
  uri = soup_uri_new (url);
  resource = !soup_uri_get_query (uri) ? g_strdup (soup_uri_get_path (uri))
                                       : g_strconcat (soup_uri_get_path (uri),
                                                      "?",
                                                      soup_uri_get_query (uri),
                                                      NULL);

  if (options && options->nonce) {
    nonce = g_strdup (options->nonce);
  } else {
    nonce = g_malloc0 (NONCE_LEN + 1);
    ephy_sync_crypto_random_hex_gen (NULL, NONCE_LEN, (guint8 *)nonce);
  }

  if (timestamp) {
    char *local_time_offset;
    gint64 offset;

    local_time_offset = options ? options->local_time_offset : NULL;
    offset = local_time_offset ? g_ascii_strtoll (local_time_offset, NULL, 10) : 0;
    ts = g_ascii_strtoll (timestamp, NULL, 10) + offset;
  }

  if (!hash && payload) {
    const char *content_type = options ? options->content_type : "text/plain";

    /* Calculate the hash for the given payload. */
    hash = ephy_sync_crypto_calculate_payload_hash (payload, content_type);
  }

  /* Create the artifacts from the options. */
  artifacts = ephy_sync_crypto_hawk_artifacts_new (options ? options->app : NULL,
                                                   options ? options->dlg : NULL,
                                                   options ? options->ext : NULL,
                                                   hash,
                                                   soup_uri_get_host (uri),
                                                   method,
                                                   nonce,
                                                   soup_uri_get_port (uri),
                                                   resource,
                                                   ts);

  header = g_strconcat ("Hawk id=\"", id, "\"",
                        ", ts=\"", artifacts->ts, "\"",
                        ", nonce=\"", artifacts->nonce, "\"",
                        NULL);

  /* Append pre-calculated payload hash if any. */
  if (artifacts->hash && strlen (artifacts->hash) > 0)
    header = ephy_sync_crypto_append_to_header (header, "hash", artifacts->hash);

  /* Append the application specific data if any. */
  if (artifacts->ext && strlen (artifacts->ext) > 0) {
    char *h_ext;
    char *tmp_ext;

    tmp_ext = ephy_sync_utils_find_and_replace (artifacts->ext, "\\", "\\\\");
    h_ext = ephy_sync_utils_find_and_replace (tmp_ext, "\n", "\\n");
    header = ephy_sync_crypto_append_to_header (header, "ext", h_ext);

    g_free (h_ext);
    g_free (tmp_ext);
  }

  /* Calculate and append a message authentication code (MAC). */
  mac = ephy_sync_crypto_calculate_mac ("header", key, key_len, artifacts);
  header = ephy_sync_crypto_append_to_header (header, "mac", mac);

  /* Append the Oz application id if any. */
  if (artifacts->app) {
    header = ephy_sync_crypto_append_to_header (header, "app", artifacts->app);

    /* Append the Oz delegated-by application id if any. */
    if (artifacts->dlg)
      header = ephy_sync_crypto_append_to_header (header, "dlg", artifacts->dlg);
  }

  soup_uri_free (uri);
  g_free (hash);
  g_free (mac);
  g_free (nonce);
  g_free (resource);

  return ephy_sync_crypto_hawk_header_new (header, artifacts);
}

SyncCryptoRSAKeyPair *
ephy_sync_crypto_generate_rsa_key_pair (void)
{
  struct rsa_public_key public;
  struct rsa_private_key private;
  int retval;

  rsa_public_key_init (&public);
  rsa_private_key_init (&private);

  /* The public exponent, usually one of the small Fermat primes 3, 5, 17, 257, 65537. */
  mpz_set_ui (public.e, 65537);

  /* Key sizes below 2048 are considered breakable and should not be used. */
  retval = rsa_generate_keypair (&public, &private,
                                 NULL, ephy_sync_crypto_random_hex_gen,
                                 NULL, NULL, 2048, 0);
  if (retval == 0) {
    g_warning ("Failed to generate RSA key pair");
    rsa_public_key_clear (&public);
    rsa_private_key_clear (&private);
    return NULL;
  }

  return ephy_sync_crypto_rsa_key_pair_new (public, private);
}

char *
ephy_sync_crypto_create_assertion (const char           *certificate,
                                   const char           *audience,
                                   guint64               duration,
                                   SyncCryptoRSAKeyPair *keypair)
{
  mpz_t signature;
  const char *header = "{\"alg\": \"RS256\"}";
  char *body;
  char *body_b64;
  char *header_b64;
  char *to_sign;
  char *sig_b64 = NULL;
  char *assertion = NULL;
  char *digest_hex;
  guint8 *digest;
  guint8 *sig = NULL;
  guint64 expires_at;
  gsize expected_size;
  gsize count;

  g_return_val_if_fail (certificate, NULL);
  g_return_val_if_fail (audience, NULL);
  g_return_val_if_fail (keypair, NULL);

  /* Encode the header and body to base64 url safe and join them. */
  expires_at = g_get_real_time () / 1000 + duration * 1000;
  body = g_strdup_printf ("{\"exp\": %lu, \"aud\": \"%s\"}", expires_at, audience);
  body_b64 = ephy_sync_crypto_base64_urlsafe_encode ((guint8 *)body, strlen (body), TRUE);
  header_b64 = ephy_sync_crypto_base64_urlsafe_encode ((guint8 *)header, strlen (header), TRUE);
  to_sign = g_strdup_printf ("%s.%s", header_b64, body_b64);

  /* Compute the SHA256 hash of the message to be signed. */
  digest_hex = g_compute_checksum_for_string (G_CHECKSUM_SHA256, to_sign, -1);
  digest = ephy_sync_crypto_decode_hex (digest_hex);

  /* Use the provided key pair to RSA sign the message. */
  mpz_init (signature);
  if (rsa_sha256_sign_digest_tr (&keypair->public, &keypair->private,
                                 NULL, ephy_sync_crypto_random_hex_gen,
                                 digest, signature) == 0) {
    g_warning ("Failed to sign the message. Giving up.");
    goto out;
  }

  expected_size = (mpz_sizeinbase (signature, 2) + 7) / 8;
  sig = g_malloc (expected_size);
  mpz_export (sig, &count, 1, sizeof (guint8), 0, 0, signature);

  if (count != expected_size) {
    g_warning ("Expected %lu bytes, got %lu. Giving up.", count, expected_size);
    goto out;
  }

  /* Finally, join certificate, header, body and signed message to create the assertion. */
  sig_b64 = ephy_sync_crypto_base64_urlsafe_encode (sig, count, TRUE);
  assertion = g_strdup_printf ("%s~%s.%s.%s", certificate, header_b64, body_b64, sig_b64);

out:
  g_free (body);
  g_free (body_b64);
  g_free (header_b64);
  g_free (to_sign);
  g_free (sig_b64);
  g_free (sig);
  g_free (digest_hex);
  g_free (digest);
  mpz_clear (signature);

  return assertion;
}

void
ephy_sync_crypto_random_hex_gen (void   *ctx,
                                 gsize   length,
                                 guint8 *dst)
{
  FILE *fp;
  gsize num_bytes;
  guint8 *bytes;
  char *hex;

  g_assert (length > 0);
  num_bytes = (length + 1) / 2;
  bytes = g_malloc (num_bytes);

  fp = fopen ("/dev/urandom", "r");
  fread (bytes, sizeof (guint8), num_bytes, fp);
  hex = ephy_sync_crypto_encode_hex (bytes, num_bytes);

  for (gsize i = 0; i < length; i++)
    dst[i] = hex[i];

  g_free (bytes);
  g_free (hex);
  fclose (fp);
}

char *
ephy_sync_crypto_base64_urlsafe_encode (guint8   *data,
                                        gsize     data_len,
                                        gboolean  strip)
{
  char *base64;
  char *out;
  gsize start = 0;
  gssize end;

  g_return_val_if_fail (data, NULL);

  base64 = g_base64_encode (data, data_len);
  end = strlen (base64) - 1;

  /* Strip the data of any leading or trailing '=' characters. */
  if (strip) {
    while (start < strlen (base64) && base64[start] == '=')
      start++;

    while (end >= 0 && base64[end] == '=')
      end--;
  }

  out = g_strndup (base64 + start, end - start + 1);
  ephy_sync_crypto_b64_to_b64_urlsafe (out);

  g_free (base64);

  return out;
}

guint8 *
ephy_sync_crypto_base64_urlsafe_decode (const char  *text,
                                        gsize       *out_len,
                                        gboolean     fill)
{
  guint8 *out;
  char *to_decode;
  char *suffix = NULL;

  g_return_val_if_fail (text, NULL);
  g_return_val_if_fail (out_len, NULL);

  /* Fill the text with trailing '=' characters up to the proper length. */
  if (fill)
    suffix = g_strnfill ((4 - strlen (text) % 4) % 4, '=');

  to_decode = g_strconcat (text, suffix, NULL);
  ephy_sync_crypto_b64_urlsafe_to_b64 (to_decode);
  out = g_base64_decode (to_decode, out_len);

  g_free (suffix);
  g_free (to_decode);

  return out;
}

guint8 *
ephy_sync_crypto_aes_256 (SyncCryptoAES256Mode  mode,
                          const guint8         *key,
                          const guint8         *data,
                          gsize                 data_len,
                          gsize                *out_len)
{
  struct aes256_ctx aes;
  gsize padded_len = data_len;
  guint8 *padded_data;
  guint8 *out;

  g_return_val_if_fail (key, NULL);
  g_return_val_if_fail (data, NULL);

  /* Since Nettle enforces the length of the data to be a multiple of
   * AES_BLOCK_SIZE, the data needs to be padded accordingly. Because any
   * data that is decrypted has to be encrypted first, crash if the length
   * is incorrect at decryption.
   */
  if (mode == AES_256_MODE_ENCRYPT)
    padded_len = data_len + (AES_BLOCK_SIZE - data_len % AES_BLOCK_SIZE);
  else if (mode == AES_256_MODE_DECRYPT)
    g_assert (data_len % AES_BLOCK_SIZE == 0);

  out = g_malloc0 (padded_len);
  padded_data = g_malloc0 (padded_len);
  memcpy (padded_data, data, data_len);

  if (mode == AES_256_MODE_ENCRYPT) {
    aes256_set_encrypt_key (&aes, key);
    aes256_encrypt (&aes, padded_len, out, padded_data);
  } else if (mode == AES_256_MODE_DECRYPT) {
    aes256_set_decrypt_key (&aes, key);
    aes256_decrypt (&aes, padded_len, out, padded_data);
  }

  if (out_len)
    *out_len = padded_len;

  g_free (padded_data);

  return out;
}

char *
ephy_sync_crypto_encode_hex (guint8 *data,
                             gsize   data_len)
{
  char *retval;
  gsize length;

  g_return_val_if_fail (data, NULL);

  length = data_len == 0 ? EPHY_SYNC_TOKEN_LENGTH : data_len;
  retval = g_malloc (length * 2 + 1);

  for (gsize i = 0; i < length; i++) {
    guint8 byte = data[i];

    retval[2 * i] = hex_digits[byte >> 4];
    retval[2 * i + 1] = hex_digits[byte & 0xf];
  }

  retval[length * 2] = 0;

  return retval;
}

guint8 *
ephy_sync_crypto_decode_hex (const char *hex)
{
  guint8 *retval;
  gsize hex_len = strlen (hex);

  g_return_val_if_fail (hex, NULL);
  g_return_val_if_fail (hex_len % 2 == 0, NULL);

  retval = g_malloc (hex_len / 2);
  for (gsize i = 0, j = 0; i < hex_len; i += 2, j++)
    sscanf(hex + i, "%2hhx", retval + j);

  return retval;
}
