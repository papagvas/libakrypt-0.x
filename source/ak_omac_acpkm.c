#include <libakrypt.h>
#include <libakrypt-internal.h>
#include <math.h>

void msb(size_t ind, size_t array_size, ak_pointer out, ak_pointer original_array) {
  for(size_t j = ind; j < array_size; j++)
    ((ak_uint8*) out)[j] = ((ak_uint8*) original_array)[j];
}

/*void shift_by_1() {
  for (int i = 
}*/

int ak_acpkm_master(ak_bckey bkey, ak_pointer in, ak_pointer out, size_t kchange_freq) {
      ak_uint8 iv[bkey->bsize / 2];
      for (size_t i = 0; i < bkey->bsize / 2; i++) {
        iv[i] = 1;
      }
      return ak_bckey_ctr_acpkm(bkey, in, out, sizeof(out), kchange_freq, iv, sizeof(iv));  
}

void xor(ak_pointer l, ak_pointer r, size_t size, ak_pointer out) {
  for (size_t i = 0; i < size; i++) {
    ((ak_uint8*)out)[i] = (((ak_uint8*) l)[i] + ((ak_uint8*) r)[i]) % 2;
  }
}

int ak_omac_acpkm(ak_bckey bkey, ak_pointer in, ak_pointer out, size_t size, size_t section_size, size_t kchange_freq) {
  const size_t n = bkey->bsize;
  const size_t k = bkey->key.key_size;
  const size_t q = ceil(((double) size) / (n * 8));
  const size_t l = ceil(((double) size) / section_size);
  ak_uint8  msg[q][n]; 
  for (size_t i = 0; i < q; i++) {
    for (size_t j = 0; j < n; j++) {
      msg[i][j] = ((ak_uint8*) in)[n*i + j];
    }
  } 
  size_t newsize = l * (k + n);
  ak_uint8 amaster_in[newsize];
  for (int i = 0; i < sizeof(amaster_in); i++) {
    amaster_in[i] = 0;
  }
  ak_uint8 newkeys[newsize];
  ak_acpkm_master(bkey, amaster_in, newkeys, kchange_freq); 
  ak_uint8 c[q-1][n];
  for (int i = 0; i < n; i++)
    c[0][i] = 0;
  for (size_t j = 1; j < q - 1;j++) {
    size_t i = j * ceil(((double) n ) / section_size);
    struct bckey tkey;
    ak_uint8 slice_of_mess[n];
    msb(0, n, slice_of_mess, msg[q-1]);
    switch (n) {
    case 8:
      ak_bckey_create_magma(&tkey);
      break;
    case 16:
      ak_bckey_create_kuznechik(&tkey);
    }
    ak_uint8 tskey[k + n / 2];
    msb((2*i - 2) * (k + n / 2), (2*i - 1) * (k + n / 2) , tskey, bkey->key.key);
    ak_bckey_set_key(&tkey, tskey, k + n);
    xor(slice_of_mess, c[j - 1], sizeof(slice_of_mess), slice_of_mess);
    ak_bckey_encrypt_ecb(&tkey, slice_of_mess, c[j], n / 8);
  }
  size_t r = sizeof(in)*8 - (q - 1) * n;
  ak_uint8 p_star[n];
  if (r == n) {
    msb(0, r, p_star, msg[q]); 
  }
  else {
    msb(0, r, p_star, msg[q]);
    p_star[r] = 1;
    for (size_t i = r + 1; i < bkey->bsize; i++) {
      p_star[i] = 0;
    }
  }
  ak_uint8 k2_prime[n];
  if (r == n) {
    ak_uint8 temp[n];
    msb((l - 1) * (k + n / 2), l * (k + n / 2), temp, newkeys);
  } 
  ak_uint8 k_prime[n];
  if (r == n)
    msb((l - 1) * (k + n / 2), l * (k + n / 2), k_prime, newkeys);
 // else 
 //   k_prime = k2_prime;
  struct bckey fkey;
  switch (n) {
    case 8:
      ak_bckey_create_magma(&fkey);
      break;
    case 16:
      ak_bckey_create_kuznechik(&fkey);
  }
  ak_uint8 finalkey[k + n / 2];
  msb((l - 2) * (k + n / 2), (l - 1) * (k + n / 2), finalkey, newkeys);
  ak_bckey_set_key(&fkey, finalkey, k + n / 2);
  xor(p_star, c[q-1], n, p_star);
  xor(p_star, k_prime, n, p_star);
  return ak_bckey_encrypt_ecb(&fkey, p_star, out, size);  
}
