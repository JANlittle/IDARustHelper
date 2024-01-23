from idaapi import *
import IDARustHelper.Demangler as Demangler
import IDARustHelper.RustType as RustType
import IDARustHelper.StringRecover.rust as StringRecover

# Register the actual plugin
class IDARustHelperHandler(plugin_t):
    PLUGIN_NAME = "IDA Rust Helper"
    PLUGIN_DIRECTORY = "IDARustHelper"
    PLUGIN_DESCRIPTION = "Rust RE Helper"

    flags = PLUGIN_UNL
    comment = PLUGIN_DESCRIPTION
    help = PLUGIN_DESCRIPTION
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        self.demangler = Demangler.IDARustDemangler(debug=False)
        self.ctx = StringRecover.rust_ctx_t(debug=False)
        return PLUGIN_OK

    def run(self, arg):
        print(f"[*] {self.PLUGIN_NAME} started!")

        self.demangler.run()
        RustType.set_rust_type()
        self.ctx.perform_final_strlit_analysis()

        print(f"[*] {self.PLUGIN_NAME} finished!")
        return 1

    def term(self):
        pass


class IDARustDemanglerHook(ida_kernwin.UI_Hooks):
    """
    this class is only used to install the icon to the corresponding IDA action
    """

    def __init__(self, cb):
        super().__init__()
        self.cb = cb

    def updated_actions(self):
        if self.cb():
            self.unhook()


def install_icon():
    plugin_name = IDARustHelperHandler.PLUGIN_NAME
    action_name = "Edit/Plugins/" + plugin_name
    LOGO_PATH = None

    # if the action is not present wait for our hook action
    if action_name not in ida_kernwin.get_registered_actions():
        return False

    # check if in any of the IDA plugins directory if there is
    # our plugin directory and take the logo from there
    for plugin_path in get_ida_subdirs("plugins"):
        LOGO_PATH = os.path.join(
            plugin_path, f"{IDARustHelperHandler.PLUGIN_DIRECTORY}\\resource\\rust-logo.png")

        # if the file exists use the first one found
        if os.path.isfile(LOGO_PATH):
            break

    if LOGO_PATH is None:
        print("[?] IDA Rust Helper logo not found")
        return True

    # load the logo and apply it to the action
    icon = load_custom_icon(
        LOGO_PATH, format="png")

    ida_kernwin.update_action_icon(action_name, icon)

    return True


def PLUGIN_ENTRY():
    return IDARustHelperHandler()


h = IDARustDemanglerHook(install_icon)
h.hook()