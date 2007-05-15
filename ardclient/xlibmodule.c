/*
 * Ardclient
 *
 * Author: Dan Keder <dan.keder@gmail.com>
 */

#include <Python.h>
#include <X11/Xlib.h>

static PyObject* xlib_getFocusedWindowTitle(PyObject *self, PyObject *args) {
    int i = 0;
    const char* display = NULL;
    Display *dpy = NULL;
    Window win;
    char* win_title = NULL;
    
    dpy = XOpenDisplay(NULL);
    if (!dpy) {
        //return NULL;
        return Py_BuildValue("s", "");
    }

    XGetInputFocus(dpy, &win, &i);
    XFetchName(dpy, win, &win_title);
    XFlush(dpy);
    XCloseDisplay(dpy);

    return Py_BuildValue("s", win_title);
}

static PyObject* xlib_getIdleTime(PyObject *self, PyObject *args) { // TODO
    int idle_time = 0;
    return Py_BuildValue("i", idle_time);
}

static PyMethodDef xlibMethods[] = {
    {"getFocusedWindowTitle",  xlib_getFocusedWindowTitle, METH_VARARGS,
        "Get focused window name."},
    {"getIdleTime",  xlib_getIdleTime, METH_VARARGS,
        "Get idle time."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC initxlib(void) {
    (void) Py_InitModule("xlib", xlibMethods);
}
