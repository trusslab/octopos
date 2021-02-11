/* OctopOS Display code */

#include <X11/Xlib.h>
#include <X11/Xutil.h>	

#include <stdio.h>
#include <stdlib.h>	
#include <unistd.h>	
// #include <MagickWand/MagickWand.h>

#include "png.h"


char* readBMP(const char* filename)
{
    int i;
    FILE* f = fopen(filename, "rb");
    char info[54];

    // read 54-byte header for bmp file
    fread(info, sizeof(char), 54, f); 

    // read image height and width from header
    int width = *(int*)&info[18];
    int height = *(int*)&info[22];

    // printf("Height: %d\n", height);
    // printf("Width: %d\n", width);

    // each pixel is 3 bytes (RGB)
    int size = 3 * width * height;
    char* data = (char*) malloc(sizeof(char) * size);

    // read the rest of the data at once
    fread(data, sizeof(char), size, f); 
    fclose(f);

    for(i = 0; i < size; i += 3)
    {
            // convert from BGR to RGB
            char tmp = data[i];
            data[i] = data[i+2];
            data[i+2] = tmp;
    }

    return data;
}


XImage *create_ximage(Display *display, Visual *visual, int width, int height)
{
        char *image32 = readPNG("peter.png");
        return XCreateImage(display, visual, 24,
                            ZPixmap, 0, image32,
                            width, height, 32, 0);
}


int main(int argc, char **argv)
{
		
        int win_b_color;
        int win_w_color;
        Window window;
        GC gc;
        Display *display = XOpenDisplay(NULL);
        Visual *visual;
        XImage *ximage;

        // printf("Default depth %d\n", DefaultDepth(display, DefaultScreen(display)));

        win_b_color = BlackPixel(display, DefaultScreen(display));
        win_w_color = BlackPixel(display, DefaultScreen(display));
        window = XCreateSimpleWindow(display,
                                DefaultRootWindow(display),
                                0, 0, 900, 900, 0,
                                win_b_color, win_w_color);

        visual = DefaultVisual(display, 0);

        XSelectInput(display, window, ExposureMask | KeyPressMask);

        XMapWindow(display, window);
        XFlush(display);
        gc = XCreateGC(display, window, 0, NULL);
        ximage = create_ximage(display, visual, 810, 500);
        XEvent event;
        bool exit = false;

        while (!exit) {
                int r;

                XNextEvent(display, &event);

                if (event.type == Expose)
                {
                    r = XPutImage(display, window,
                            gc, ximage, 10, 10, 10, 10,
                            810, 500);
                    printf("Status: %i\n", r);
                }
                else if (event.type == KeyPress)
                    exit = true;
        }

        return 0;
}
