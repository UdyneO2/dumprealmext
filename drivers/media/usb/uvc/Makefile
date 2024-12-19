# SPDX-License-Identifier: GPL-2.0
uvcvideo-objs  := uvc_driver.o uvc_queue.o uvc_v4l2.o uvc_video.o uvc_ctrl.o \
<<<<<<< HEAD
		  uvc_status.o uvc_isight.o uvc_debugfs.o uvc_metadata.o
=======
		  uvc_status.o uvc_isight.o uvc_metadata.o
ifdef CONFIG_DEBUG_FS
uvcvideo-objs  += uvc_debugfs.o
endif
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
ifeq ($(CONFIG_MEDIA_CONTROLLER),y)
uvcvideo-objs  += uvc_entity.o
endif
obj-$(CONFIG_USB_VIDEO_CLASS) += uvcvideo.o
