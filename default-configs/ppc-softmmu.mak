# Default configuration for ppc-softmmu

include pci.mak
include sound.mak
include usb.mak

# For embedded PPCs:
CONFIG_PPC4XX=y
CONFIG_M48T59=y
CONFIG_SERIAL=y
CONFIG_I8257=y
CONFIG_OPENPIC=y
CONFIG_PPCE500_PCI=y
CONFIG_PFLASH_CFI01=y
CONFIG_PFLASH_CFI02=y
CONFIG_PTIMER=y
CONFIG_I8259=y
CONFIG_XILINX=y
CONFIG_XILINX_ETHLITE=y
CONFIG_E500=y
CONFIG_OPENPIC_KVM=$(call land,$(CONFIG_E500),$(CONFIG_KVM))
CONFIG_PLATFORM_BUS=y
CONFIG_ETSEC=y
# For Sam460ex
CONFIG_USB_EHCI_SYSBUS=y
CONFIG_SM501=y
CONFIG_IDE_SII3112=y
CONFIG_I2C=y

# For Macs
CONFIG_MAC=y
CONFIG_ESCC=y
CONFIG_MACIO=y
CONFIG_MACIO_GPIO=y
CONFIG_SUNGEM=y
CONFIG_MOS6522=y
CONFIG_CUDA=y
CONFIG_ADB=y
CONFIG_MAC_NVRAM=y
CONFIG_MAC_DBDMA=y
CONFIG_MAC_PMU=y
CONFIG_HEATHROW_PIC=y
CONFIG_GRACKLE_PCI=y
CONFIG_UNIN_PCI=y
CONFIG_DEC_PCI=y
CONFIG_IDE_MACIO=y

# For PReP
CONFIG_PREP=y
CONFIG_PREP_PCI=y
CONFIG_SERIAL_ISA=y
CONFIG_MC146818RTC=y
CONFIG_ISA_TESTDEV=y
CONFIG_RS6000_MC=y
CONFIG_PARALLEL=y
CONFIG_I82374=y
CONFIG_I82378=y
CONFIG_I8254=y
CONFIG_PCKBD=y
CONFIG_FDC=y
CONFIG_NE2000_ISA=y
CONFIG_PC87312=y
CONFIG_PCSPK=y
CONFIG_IDE_ISA=y
CONFIG_CS4231A=y
