#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>
#include <crypto/scatterwalk.h> 

//enum chacha20poly1305_lengths {
//	XCHACHA20POLY1305_NONCE_SIZE = 24,
//	CHACHA20POLY1305_KEY_SIZE = 32,
//	CHACHA20POLY1305_AUTHTAG_SIZE = 16
//};

static int encrypt_skcipher(u8 *src,
	const u8 key[CHACHA20POLY1305_KEY_SIZE],
	const size_t src_len)
{
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	u8 *data = NULL;
	const size_t datasize = 512; /* data size in bytes */
	DECLARE_CRYPTO_WAIT(wait);
	u8 iv[16];  /* AES-256-XTS takes a 16-byte IV */ //TODO
	//u8 key[64]; /* AES-256-XTS takes a 64-byte key */
	int err;

	/*
	 * Allocate a tfm (a transformation object) and set the key.
	 *
	 * In real-world use, a tfm and key are typically used for many
	 * encryption/decryption operations.  But in this example, we'll just do a
	 * single encryption operation with it (which is not very efficient).
	 */

	tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Error allocating xts(aes) handle: %ld\n", PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	//get_random_bytes(key, sizeof(key));
	err = crypto_skcipher_setkey(tfm, key, sizeof(key));
	if (err) {
		pr_err("Error setting key: %d\n", err);
		goto out;
	}

	/* Allocate a request object */
	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto out;
	}

	/* Prepare the input data */
	//data = kmalloc(datasize, GFP_KERNEL);
	//if (!data) {
	//	err = -ENOMEM;
	//	goto out;
	//}
	//get_random_bytes(data, datasize);

	/* Initialize the IV */
	get_random_bytes(iv, sizeof(iv)); //TODO: using random iv for now

	/*
	 * Encrypt the data in-place.
	 *
	 * For simplicity, in this example we wait for the request to complete
	 * before proceeding, even if the underlying implementation is asynchronous.
	 *
	 * To decrypt instead of encrypt, just change crypto_skcipher_encrypt() to
	 * crypto_skcipher_decrypt().
	 */
	//sg_init_one(&sg, data, datasize);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
		CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);
	skcipher_request_set_crypt(req, src, src, src_len, iv);
	err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	if (err) {
		pr_err("Error encrypting data: %d\n", err);
		goto out;
	}

	printk("%s","Encryption was successful\n");
out:
	crypto_free_skcipher(tfm);
	skcipher_request_free(req);
	kfree(data);
	return err;
}

static int decrypt_skcipher(u8 *src,
	const u8 key[CHACHA20POLY1305_KEY_SIZE],
	const size_t src_len)
{
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	u8 *data = NULL;
	const size_t datasize = 512; /* data size in bytes */
	DECLARE_CRYPTO_WAIT(wait);
	u8 iv[16];  /* AES-256-XTS takes a 16-byte IV */ //TODO
	//u8 key[64]; /* AES-256-XTS takes a 64-byte key */
	int err;

	/*
	 * Allocate a tfm (a transformation object) and set the key.
	 *
	 * In real-world use, a tfm and key are typically used for many
	 * encryption/decryption operations.  But in this example, we'll just do a
	 * single encryption operation with it (which is not very efficient).
	 */

	tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Error allocating xts(aes) handle: %ld\n", PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	//get_random_bytes(key, sizeof(key));
	err = crypto_skcipher_setkey(tfm, key, sizeof(key));
	if (err) {
		pr_err("Error setting key: %d\n", err);
		goto out;
	}

	/* Allocate a request object */
	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto out;
	}

	/* Prepare the input data */
	data = kmalloc(datasize, GFP_KERNEL);
	if (!data) {
		err = -ENOMEM;
		goto out;
	}
	//get_random_bytes(data, datasize);

	/* Initialize the IV */
	get_random_bytes(iv, sizeof(iv)); //TODO: using random iv for now

	/*
	 * Encrypt the data in-place.
	 *
	 * For simplicity, in this example we wait for the request to complete
	 * before proceeding, even if the underlying implementation is asynchronous.
	 *
	 * To decrypt instead of encrypt, just change crypto_skcipher_encrypt() to
	 * crypto_skcipher_decrypt().
	 */
	 //sg_init_one(&sg, data, datasize);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
		CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);
	skcipher_request_set_crypt(req, src, src, src_len, iv);
	err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	if (err) {
		pr_err("Error encrypting data: %d\n", err);
		goto out;
	}

	printk("%s", "Encryption was successful\n");
out:
	crypto_free_skcipher(tfm);
	skcipher_request_free(req);
	kfree(data);
	return err;
}