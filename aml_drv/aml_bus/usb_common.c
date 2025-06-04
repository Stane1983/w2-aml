
#define AML_MODULE  COMMON

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/clock.h>
#endif

#include "usb_common.h"
#include "chip_ana_reg.h"
#include "wifi_intf_addr.h"
#include "sg_common.h"
#include "fi_sdio.h"
#include "w2_usb.h"
#include "aml_interface.h"
#include "fi_w2_sdio.h"
#include "chip_intf_reg.h"
#include "aml_interface.h"
#include "chip_bt_pmu_reg.h"
#include "aml_log.h"

struct auc_hif_ops g_auc_hif_ops;
struct usb_device *g_udev = NULL;
struct aml_hwif_usb g_hwif_usb;
unsigned char auc_driver_insmoded;
unsigned char auc_wifi_in_insmod;
unsigned char g_chip_function_ctrl = 0;
unsigned char g_usb_after_probe;
struct crg_msc_cbw *g_cmd_buf = NULL;
struct mutex auc_usb_mutex;
unsigned char *g_kmalloc_buf;
extern unsigned char wifi_drv_rmmod_ongoing;
extern struct aml_bus_state_detect bus_state_detect;
extern struct aml_pm_type g_wifi_pm;
extern void auc_w2_ops_init(void);
extern void extern_wifi_set_enable(int is_on);

/*for bluetooth get read/write point*/
int bt_wt_ptr = 0;
int bt_rd_ptr = 0;
/*co-exist flag for bt/wifi mode*/
int coex_flag = 0;
struct wakeup_source *aml_wifi_wakeup_source;

static int auc_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
    g_udev = usb_get_dev(interface_to_usbdev(interface));
    memset(g_kmalloc_buf,0,1024*20);
    memset(g_cmd_buf,0,sizeof(struct crg_msc_cbw ));

    auc_w2_ops_init();
    g_auc_hif_ops.hi_enable_scat();
#ifdef CONFIG_PM
    if (atomic_read(&g_wifi_pm.bus_suspend_cnt)) {
        atomic_set(&g_wifi_pm.bus_suspend_cnt, 0);
    }
#endif
    PRINT("%s(%d)\n",__func__,__LINE__);

    g_usb_after_probe = 1;
    return 0;
}


static void auc_disconnect(struct usb_interface *interface)
{
    usb_set_intfdata(interface, NULL);
    usb_put_dev(g_udev);
    g_usb_after_probe = 0;
    atomic_set(&g_wifi_pm.bus_suspend_cnt, 0);
    atomic_set(&g_wifi_pm.drv_suspend_cnt, 0);
    AML_INFO("--------aml_usb:disconnect-------\n");
}

#ifdef CONFIG_PM
static int auc_reset_resume(struct usb_interface *interface)
{
    atomic_set(&g_wifi_pm.bus_suspend_cnt, 0);
    AML_INFO("--------aml_usb:reset done-------\n");
    return 0;
}

static int auc_suspend(struct usb_interface *interface,pm_message_t state)
{
    u64 start_time_ns;
    u64 elapsed_time_ns = 0;
    u64 wait_bt_time_ns = 8000000000; //wait bt 8s
    u64 wait_wifi_time_ns = 12000000000; //wait wifi 12s

    AML_INFO("auc_suspend!! \n");

    //bt open
    if ((auc_read_word_by_ep_for_bt(RG_BT_PMU_A16, USB_EP1) & BIT(31)))
    {
        start_time_ns = sched_clock();
        //bt drv suspend set bit25
        while ((auc_read_word_by_ep_for_bt(RG_AON_A24, USB_EP1) & BIT(25)) &&
                (bus_state_detect.bus_err == 0) &&
                (bus_state_detect.is_recy_ongoing == 0) &&
                (elapsed_time_ns < wait_bt_time_ns))
        {
            elapsed_time_ns = sched_clock() - start_time_ns;
            msleep(10);
        }

        if (elapsed_time_ns >= wait_bt_time_ns)
        {
            AML_INFO("bt suspend fail, return\n");
        }

        // Detect a bus error or ongoing recovery,
        // exit immediately to prevent blocking the kernel USB resume call.
        if (bus_state_detect.bus_err || bus_state_detect.is_recy_ongoing)
        {
            AML_INFO("Detect a bus error or ongoing recovery, return\n");
            return 0;
        }
    }

    elapsed_time_ns = 0;
    if (atomic_read(&g_wifi_pm.wifi_enable))
    {
        start_time_ns = sched_clock();
        while ((atomic_read(&g_wifi_pm.drv_suspend_cnt) == 0) &&
                (bus_state_detect.bus_err == 0) &&
                (bus_state_detect.is_recy_ongoing == 0) &&
                (atomic_read(&g_wifi_pm.wifi_suspend_state) == 0) &&
                (elapsed_time_ns < wait_wifi_time_ns))
        {
            elapsed_time_ns = sched_clock() - start_time_ns;
            msleep(10);
        }

        if (elapsed_time_ns >= wait_wifi_time_ns)
        {
            AML_INFO("wifi suspend fail, return\n");
        }

        if (atomic_read(&g_wifi_pm.wifi_suspend_state) != 0)
        {
            AML_INFO("Detect wifi suspend fail\n");
            return 0;
        }

        // Detect a bus error or ongoing recovery,
        // exit immediately to prevent blocking the kernel USB resume call.
        if (bus_state_detect.bus_err || bus_state_detect.is_recy_ongoing)
        {
            AML_INFO("Detect a bus error or ongoing recovery, return\n");
            return 0;
        }
    }

    atomic_set(&g_wifi_pm.bus_suspend_cnt, 1);
    AML_INFO("---------aml_usb suspend-------\n");
    return 0;
}

static int auc_resume(struct usb_interface *interface)
{
    AML_INFO("auc_resume!! \n");

    atomic_set(&g_wifi_pm.bus_suspend_cnt, 0);
    return 0;
}
#endif

extern lp_shutdown_func g_lp_shutdown_func;
extern bt_shutdown_func g_bt_shutdown_func;

void auc_shutdown(struct device *dev)
{
    AML_INFO(" auc_shutdown begin \n");

    //Mask interrupt reporting to the host
    atomic_set(&g_wifi_pm.is_shut_down, 2);

    // Notify fw to enter shutdown mode
    if (g_bt_shutdown_func != NULL)
    {
        g_bt_shutdown_func();
    }

    if (g_lp_shutdown_func != NULL)
    {
        g_lp_shutdown_func();
    }

    //notify fw shutdown
    //notify bt wifi will go shutdown
    auc_write_word_by_ep_for_wifi(RG_AON_A16, auc_read_word_by_ep_for_wifi(RG_AON_A16, USB_EP4)|BIT(28) ,USB_EP4);

    atomic_set(&g_wifi_pm.is_shut_down, 1);
}

static const struct usb_device_id auc_devices[] =
{
    {USB_DEVICE(W2_VENDOR,W2_PRODUCT)},
    {USB_DEVICE(W2u_VENDOR_AMLOGIC_EFUSE,W2u_PRODUCT_A_AMLOGIC_EFUSE)},
    {USB_DEVICE(W2u_VENDOR_AMLOGIC_EFUSE,W2u_PRODUCT_B_AMLOGIC_EFUSE)},
    {}
};

MODULE_DEVICE_TABLE(usb, auc_devices);

static struct usb_driver aml_usb_common_driver = {

    .name = "aml_usb_common",
    .id_table = auc_devices,
    .probe = auc_probe,
    .disconnect = auc_disconnect,
#ifdef CONFIG_PM
    .reset_resume = auc_reset_resume,
    .suspend = auc_suspend,
    .resume = auc_resume,
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6, 8, 0)
    .drvwrap.driver.shutdown = auc_shutdown,
#endif
};

/**
 * aml_set_bus_err - Set the bus error state and handle system wakeup
 *
 * Updates the bus error state. If `bus_err` is non-zero, and if the
 * wakeup source is initialized but not active, the system is kept awake
 * to prevent suspend during recovery.
 *
 * @bus_err: The bus error state. A non-zero value indicates an error.
 */
void aml_set_bus_err(unsigned char bus_err)
{
    if (bus_err) {
        // Wake up the system and prevent it from entering
        // suspend during the upcoming recovery process.
        if (aml_wifi_wakeup_source && (!aml_wifi_wakeup_source->active)) {
            __pm_stay_awake(aml_wifi_wakeup_source);
        } else {
            PRINT("aml_wifi_wakeup_source is not initialized or active already\n");
        }
    }

    bus_state_detect.bus_err = bus_err;

    PRINT("Bus error state updated: %d\n", bus_err);
}

int aml_usb_insmod(void)
{
    int err = 0;

    g_cmd_buf = ZMALLOC(sizeof(*g_cmd_buf), "cmd stage", GFP_DMA | GFP_ATOMIC);
    if (!g_cmd_buf) {
        PRINT("g_cmd_buf malloc fail\n");
        return -ENOMEM;
    }
    g_kmalloc_buf = (unsigned char *)ZMALLOC(20*1024, "reg tmp", GFP_DMA | GFP_ATOMIC);
    if (!g_kmalloc_buf) {
        ERROR_DEBUG_OUT("data malloc fail\n");
        FREE(g_cmd_buf, "cmd stage");
        return -ENOMEM;
    }
    err = usb_register(&aml_usb_common_driver);
    if (err) {
        PRINT("failed to register usb driver: %d \n", err);
    }
    auc_driver_insmoded = 1;
    auc_wifi_in_insmod = 0;
    USB_LOCK_INIT();
    PRINT("%s(%d) aml common driver insmod\n", __func__, __LINE__);

    aml_wifi_wakeup_source = wakeup_source_register(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
             NULL,
#endif
             "aml_wifi_wakeup_source");
    if (!aml_wifi_wakeup_source) {
        PRINT("Failed to create wakeup source\n");
        return -ENOMEM;
    }

    return err;
}

void aml_usb_rmmod(void)
{
    usb_deregister(&aml_usb_common_driver);
    auc_driver_insmoded = 0;
    wifi_drv_rmmod_ongoing = 0;
    g_auc_hif_ops.hi_cleanup_scat();
    FREE(g_cmd_buf, "cmd stage");
    FREE(g_kmalloc_buf, "reg tmp");
    USB_LOCK_DESTROY();
#ifndef CONFIG_PT_MODE
#ifndef CONFIG_LINUXPC_VERSION
    extern_wifi_set_enable(0);
    msleep(100);
    extern_wifi_set_enable(1);
#endif
#endif
    if (aml_wifi_wakeup_source) {
        wakeup_source_unregister(aml_wifi_wakeup_source);
        aml_wifi_wakeup_source = NULL;
    } else {
        PRINT("aml_wifi_wakeup_source is not initialized, unregistering is not required.\n");
    }
   PRINT("%s(%d) aml common driver rmsmod\n",__func__, __LINE__);
}
void aml_usb_reset(void)
{
    uint32_t count = 0;
    uint32_t try_cnt = 0;

Try_again:
    AML_INFO(" ******* usb reset begin *******\n");

#ifndef CONFIG_PT_MODE

#ifndef CONFIG_LINUXPC_VERSION
    extern_wifi_set_enable(0);
    while ((g_usb_after_probe) && (try_cnt <= 3)) {
        msleep(5);
        count++;
        if (count > 40 && try_cnt <= 3) {
            count = 0;
            try_cnt++;
            extern_wifi_set_enable(1);
            msleep(50);
            AML_ERR(" usb reset fail, try again(%d)\n", try_cnt);
            goto Try_again;
        }
    }
    extern_wifi_set_enable(1);
#endif

    count = 0;
    try_cnt = 0;
    while ((!g_usb_after_probe) && try_cnt <= 3) {
        msleep(5);
        count++;
        if (count > 200) {
            count = 0;
            try_cnt++;
            AML_ERR(" usb reset fail, try again(%d)\n", try_cnt);
            goto Try_again;
        }
    };
    bus_state_detect.bus_reset_ongoing = 0;
    bus_state_detect.bus_err = 0;
    AML_INFO(" ******* usb reset end *******\n");

    return;
#endif
}
EXPORT_SYMBOL(aml_usb_reset);
EXPORT_SYMBOL(aml_usb_insmod);
EXPORT_SYMBOL(aml_usb_rmmod);
EXPORT_SYMBOL(g_cmd_buf);
EXPORT_SYMBOL(g_auc_hif_ops);
EXPORT_SYMBOL(g_udev);
EXPORT_SYMBOL(auc_driver_insmoded);
EXPORT_SYMBOL(auc_wifi_in_insmod);
EXPORT_SYMBOL(auc_usb_mutex);
EXPORT_SYMBOL(g_usb_after_probe);
EXPORT_SYMBOL(bt_wt_ptr);
EXPORT_SYMBOL(bt_rd_ptr);
EXPORT_SYMBOL(coex_flag);
EXPORT_SYMBOL(g_chip_function_ctrl);
EXPORT_SYMBOL(aml_wifi_wakeup_source);

EXPORT_SYMBOL(aml_set_bus_err);

