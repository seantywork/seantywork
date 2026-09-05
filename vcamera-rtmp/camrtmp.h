#ifndef _CAM_RTMP_
#define _CAM_RTMP_

#include <stdio.h>
#include <gst/gst.h>

#define MUXER_BATCH_TIMEOUT_USEC 400000


#define ENC_SPEED_PRESET_ULTRAFAST 1
#define ENC_TUNE_ZEROLATENCY  0x00000004

gboolean bus_call (GstBus * bus, GstMessage * msg, gpointer data);



/*


gst-launch-1.0 
  -e v4l2src device=/dev/video0 
  ! queue 
  ! videoconvert 
  ! videoscale 
  ! video/x-raw,width=960,height=720 
  ! x264enc speed-preset=ultrafast tune=zerolatency key-int-max=20 
  ! flvmux streamable=true 
  ! queue 
  ! rtmpsink location='rtmps://localhost:8084/publish/foobar'

*/


/*

gst-launch-1.0
  libcamerasrc 
  ! queue 
  ! videoconvert 
  ! videoscale 
  ! video/x-raw,width=640,height=480 
  ! x264enc speed-preset=ultrafast tune=zerolatency key-int-max=20 
  ! flvmux streamable=true name=mux 
  ! queue 
  ! rtmpsink location='rtmps://localhost:8084/publish/foobar' 

*/

#endif