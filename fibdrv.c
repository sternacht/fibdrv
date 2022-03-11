#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");
MODULE_DESCRIPTION("Fibonacci engine driver");
MODULE_VERSION("0.1");

#define DEV_FIBONACCI_NAME "fibonacci"

/* MAX_LENGTH is set to 92 because
 * ssize_t can't fit the number > 92
 */
#define MAX_LENGTH 500

static dev_t fib_dev = 0;
static struct cdev *fib_cdev;
static struct class *fib_class;
static DEFINE_MUTEX(fib_mutex);

#define INT32_M 0xFFFFFFFF
#define INT32_H 0x80000000

typedef struct {
    int len;
    __u32 *bn;
} bignum;

bignum bignum_init(unsigned int l)
{
    if (!l)
        l = 1;
    bignum a;
    a.len = l;
    a.bn = kmalloc(sizeof(__u32) * l, GFP_KERNEL);
    memset(a.bn, 0, sizeof(__u32) * l);
    return a;
}

void bignum_check(bignum *a)
{
    for (int i = a->len; i--;) {
        if (*(a->bn + i))
            break;
        (a->len)--;
    }
    a->len = (a->len > 0) ? a->len : 1;
    a->bn = krealloc(a->bn, sizeof(__u32) * a->len, GFP_KERNEL);
    return;
}

void bignum_add(bignum a, bignum b, bignum *ret)
{
    ret->len = b.len + 1;
    __u32 *bn = kmalloc(sizeof(__u32) * (ret->len), GFP_KERNEL);
    // c stand for 'carry or not'
    int i = 0, c = 0;
    while (i < a.len) {
        *(bn + i) = *(a.bn + i) + *(b.bn + i) + c;
        c = (*(bn + i) < *(a.bn + i)) ? 1 : 0;
        i++;
    }

    while (i < b.len) {
        *(bn + i) = *(b.bn + i) + c;
        c = (*(bn + i) < *(b.bn + i)) ? 1 : 0;
        i++;
    }
    *(bn + i) = c;

    kfree(ret->bn);
    ret->bn = bn;
    bignum_check(ret);
    return;
}

void bignum_sub(bignum a, bignum b, bignum *ret)
{
    ret->len = a.len;
    __u32 *bn = kmalloc(sizeof(__u32) * (ret->len), GFP_KERNEL);

    int i = 0, c = 0;
    while (i < b.len) {
        *(bn + i) = *(a.bn + i) - *(b.bn + i) - c;
        c = (*(b.bn + i) + c > *(a.bn + i)) ? 1 : 0;
        i++;
    }
    while (i < a.len) {
        *(bn + i) = *(a.bn + i) - c;
        c = *(a.bn + i) ? 0 : 1;
        i++;
    }

    kfree(ret->bn);
    ret->bn = bn;
    bignum_check(ret);
    return;
}

void bignum_mul(bignum a, bignum b, bignum *ret)
{
    // bignum ret = bignum_init(a.len + b.len);
    ret->len = a.len + b.len;
    __u32 *bn = kcalloc(ret->len, sizeof(__u32), GFP_KERNEL);

    int i, j;
    for (i = 0; i < a.len; i++) {
        int uc = 0;
        for (j = 0; j < b.len; j++) {
            int lc = 0;
            __u64 tmp = (__u64)(*(a.bn + i)) * (u64)(*(b.bn + j));
            *(bn + i + j) += (tmp & INT32_M);
            lc = (*(bn + i + j) < (tmp & INT32_M)) ? 1 : 0;
            *(bn + i + j + 1) += (__u32)(tmp >> 32) + lc + uc;
            uc = (*(bn + i + j + 1) < (__u32)(tmp >> 32)) ? 1 : 0;
        }
        *(bn + i + j) += uc;
    }
    kfree(ret->bn);
    ret->bn = bn;
    bignum_check(ret);
    return;
}

void bignum_free(bignum a)
{
    kfree(a.bn);
    a.bn = NULL;
    return;
}

char *bignum2dec(bignum a)
{
    int slen = 32 * (a.len) / 3 + 2;
    char *s = kmalloc(sizeof(char) * slen, GFP_KERNEL);
    __u32 *n = kmalloc(sizeof(__u32) * a.len, GFP_KERNEL);
    int i;

    memset(s, '0', slen - 1);
    s[slen - 1] = '\0';
    memcpy(n, a.bn, a.len * sizeof(__u32));

    for (i = 0; i < 32 * a.len; i++) {
        int j, c, l = a.len;
        c = (n[l - 1] >= INT32_H);
        while (--l) {
            n[l] = ((n[l] << 1) & INT32_M) + (n[l - 1] >= INT32_H);
        }
        n[0] = ((n[0] << 1) & INT32_M);

        for (j = slen - 2; j >= 0; j--) {
            s[j] += s[j] - '0' + c;
            c = (s[j] > '9');
            if (c)
                s[j] -= 10;
        }
    }
    i = 0;
    while (i < slen - 2 && s[i] == '0')
        i++;
    char *p = kmalloc(slen - i, GFP_KERNEL);
    memcpy(p, s + i, slen - i);
    kfree(s);
    kfree(n);
    return p;
}
/* unused
bignum bignum_fib(unsigned int n)
{
    bignum a = bignum_init(1), b = bignum_init(1);
    *(b.bn) = 1;
    bignum tmp;
    for (; n; n--) {
        tmp = b;
        bignum_add(a, b, &b);
        a = tmp;
    }
    bignum_free(b);
    return a;
}
*/
void bignum_copy(bignum *a, bignum b)
{
    a->len = b.len;
    a->bn = krealloc(a->bn, sizeof(__u32) * a->len, GFP_KERNEL);
    memcpy(a->bn, b.bn, sizeof(__u32) * a->len);
    return;
}

char *fast_doubling(int n)
{
    bignum a = bignum_init(1), b = bignum_init(1);
    *(b.bn) = 1;
    if (!n)
        goto end;
    bignum t1 = bignum_init(1), t2 = bignum_init(1);
    for (int i = 32 - __builtin_clz(n); i--;) {
        // t2 = a * a + b * b
        bignum_mul(a, a, &t1);
        bignum_mul(b, b, &t2);
        bignum_add(t1, t2, &t2);
        // t1 = a * (2 * b - a)
        bignum_add(b, b, &t1);
        bignum_sub(t1, a, &t1);
        bignum_mul(t1, a, &t1);
        bignum_copy(&a, t1);
        bignum_copy(&b, t2);
        if (n & (1 << i)) {
            bignum_add(a, b, &t1);
            bignum_copy(&a, b);
            bignum_copy(&b, t1);
        }
    }
    bignum_free(t1);
    bignum_free(t2);
end:
    bignum_free(b);
    char *ret = bignum2dec(a);
    bignum_free(a);
    return ret;
}
/* unused
static long long fib_sequence(long long k)
{
    long long *f = kmalloc(sizeof(long long) * (k + 2), GFP_KERNEL);

    f[0] = 0;
    f[1] = 1;

    for (int i = 2; i <= k; i++) {
        f[i] = f[i - 1] + f[i - 2];
    }
    long long ret = f[k];
    kfree(f);
    return ret;
}
*/

static int fib_open(struct inode *inode, struct file *file)
{
    if (!mutex_trylock(&fib_mutex)) {
        printk(KERN_ALERT "fibdrv is in use");
        return -EBUSY;
    }
    return 0;
}

static int fib_release(struct inode *inode, struct file *file)
{
    mutex_unlock(&fib_mutex);
    return 0;
}

/* calculate the fibonacci number at given offset */
static ssize_t fib_read(struct file *file,
                        char *buf,
                        size_t size,
                        loff_t *offset)
{
    // ktime_t t1 = ktime_get();
    char *ret = fast_doubling(*offset);
    copy_to_user(buf, ret, strlen(ret) + 1);
    kfree(ret);
    // t1 = ktime_sub(ktime_get(), t1);

    // ktime_t t2 = ktime_get();
    // fast_doubling(*offset);
    // t2 = ktime_sub(ktime_get(), t2);

    // printk(KERN_INFO "%d %lld %lld", *offset, ktime_to_ns(t1),
    //       ktime_to_ns(t2));

    return 0;
}

/* write operation is skipped */
static ssize_t fib_write(struct file *file,
                         const char *buf,
                         size_t size,
                         loff_t *offset)
{
    return 1;
}

static loff_t fib_device_lseek(struct file *file, loff_t offset, int orig)
{
    loff_t new_pos = 0;
    switch (orig) {
    case 0: /* SEEK_SET: */
        new_pos = offset;
        break;
    case 1: /* SEEK_CUR: */
        new_pos = file->f_pos + offset;
        break;
    case 2: /* SEEK_END: */
        new_pos = MAX_LENGTH - offset;
        break;
    }

    if (new_pos > MAX_LENGTH)
        new_pos = MAX_LENGTH;  // max case
    if (new_pos < 0)
        new_pos = 0;        // min case
    file->f_pos = new_pos;  // This is what we'll use now
    return new_pos;
}

const struct file_operations fib_fops = {
    .owner = THIS_MODULE,
    .read = fib_read,
    .write = fib_write,
    .open = fib_open,
    .release = fib_release,
    .llseek = fib_device_lseek,
};

static int __init init_fib_dev(void)
{
    int rc = 0;

    mutex_init(&fib_mutex);

    // Let's register the device
    // This will dynamically allocate the major number
    rc = alloc_chrdev_region(&fib_dev, 0, 1, DEV_FIBONACCI_NAME);

    if (rc < 0) {
        printk(KERN_ALERT
               "Failed to register the fibonacci char device. rc = %i",
               rc);
        return rc;
    }

    fib_cdev = cdev_alloc();
    if (fib_cdev == NULL) {
        printk(KERN_ALERT "Failed to alloc cdev");
        rc = -1;
        goto failed_cdev;
    }
    fib_cdev->ops = &fib_fops;
    rc = cdev_add(fib_cdev, fib_dev, 1);

    if (rc < 0) {
        printk(KERN_ALERT "Failed to add cdev");
        rc = -2;
        goto failed_cdev;
    }

    fib_class = class_create(THIS_MODULE, DEV_FIBONACCI_NAME);

    if (!fib_class) {
        printk(KERN_ALERT "Failed to create device class");
        rc = -3;
        goto failed_class_create;
    }

    if (!device_create(fib_class, NULL, fib_dev, NULL, DEV_FIBONACCI_NAME)) {
        printk(KERN_ALERT "Failed to create device");
        rc = -4;
        goto failed_device_create;
    }
    return rc;
failed_device_create:
    class_destroy(fib_class);
failed_class_create:
    cdev_del(fib_cdev);
failed_cdev:
    unregister_chrdev_region(fib_dev, 1);
    return rc;
}

static void __exit exit_fib_dev(void)
{
    mutex_destroy(&fib_mutex);
    device_destroy(fib_class, fib_dev);
    class_destroy(fib_class);
    cdev_del(fib_cdev);
    unregister_chrdev_region(fib_dev, 1);
}

module_init(init_fib_dev);
module_exit(exit_fib_dev);
