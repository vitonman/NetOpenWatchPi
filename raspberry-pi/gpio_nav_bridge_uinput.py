from gpiozero import Button, RotaryEncoder
from signal import pause
from evdev import UInput, ecodes as e


# GPIO pin numbers use the BCM numbering scheme.
btn_mode = Button(23, pull_up=True, bounce_time=0.08)
btn_back = Button(24, pull_up=True, bounce_time=0.08)

enc1 = RotaryEncoder(a=17, b=27, wrap=False, max_steps=0)
btn_enc1 = Button(22, pull_up=True, bounce_time=0.08)


ui = UInput(
    {
        e.EV_KEY: [
            e.KEY_M,
            e.KEY_ESC,
            e.KEY_ENTER,
            e.KEY_UP,
            e.KEY_DOWN,
        ]
    },
    name="NetOpenWatchPi GPIO Keyboard",
    version=0x3,
)


def tap(code):
    ui.write(e.EV_KEY, code, 1)
    ui.write(e.EV_KEY, code, 0)
    ui.syn()


def down(code):
    ui.write(e.EV_KEY, code, 1)
    ui.syn()


def up(code):
    ui.write(e.EV_KEY, code, 0)
    ui.syn()


btn_mode.when_pressed = lambda: tap(e.KEY_M)

# Keep ESC pressed while BACK is held, so nav.js can detect long press.
btn_back.when_pressed = lambda: down(e.KEY_ESC)
btn_back.when_released = lambda: up(e.KEY_ESC)

btn_enc1.when_pressed = lambda: tap(e.KEY_ENTER)

enc1.when_rotated_clockwise = lambda: tap(e.KEY_DOWN)
enc1.when_rotated_counter_clockwise = lambda: tap(e.KEY_UP)


print("GPIO nav bridge (uinput) started")
pause()
