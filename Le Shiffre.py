import tkinter
from tkinter import filedialog as fd
import rsa


class Application(tkinter.Tk):
    def encode(self):
        filename = self.entry1.get()
        with open(filename, "rb") as file:
            pub = file.read()
        pubkey = rsa.PublicKey.load_pkcs1(pub)
        self.encode_output.delete('1.0', tkinter.END)
        for line in self.encode_input.get('1.0', 'end-1c').splitlines():
            if line:
                message = line+'\n'
                message = message.encode('utf-8')
                message = rsa.encrypt(message, pubkey)
                self.encode_output.insert(tkinter.END, message)

    def decode(self):
        filename = self.entry2.get()
        with open(filename, "rb") as file:
            priv = file.read()
        privkey = rsa.PrivateKey.load_pkcs1(priv)
        self.decode_output.delete('1.0', tkinter.END)
        for line in self.decode_input.get('1.0', 'end-1c').splitlines():
            if line:
                message = line.encode('utf-8')
                message = rsa.decrypt(message, privkey)
                self.decode_output.insert(tkinter.END, message)

    def init_keys(self):
        (pub, priv) = rsa.newkeys(512)
        with open("private_key.pem", "wb") as file:
            file.write(priv.save_pkcs1())
        with open("public_key.pem", "wb") as file:
            file.write(pub.save_pkcs1())


    def add_public_key(self):
        file_name = fd.askopenfilename()
        self.entry1.delete(0, tkinter.END)
        self.entry1.insert(0, file_name)

    def add_private_key(self):
        file_name = fd.askopenfilename()
        self.entry2.delete(0, tkinter.END)
        self.entry2.insert(0, file_name)

    def __init__(self):
        super().__init__()
        self.title("Шифр")
        self.pubkey_frame = tkinter.Frame(master=self, bg="white", bd=2)
        self.privatekey_frame = tkinter.Frame(master=self, bg="white", bd=2)
        self.code_frame = tkinter.Frame(master=self, bg="white", bd=2)

        self.entry1 = tkinter.Entry(master=self.pubkey_frame, justify=tkinter.LEFT)
        self.label1 = tkinter.Label(master=self.pubkey_frame, width=10, text="PUB: ")
        self.button1 = tkinter.Button(master=self.pubkey_frame, text="Select file", relief=tkinter.FLAT, command=self.add_public_key)

        self.entry2 = tkinter.Entry(master=self.privatekey_frame, justify=tkinter.RIGHT)
        self.label2 = tkinter.Label(master=self.privatekey_frame, width=10, text="PRV: ")
        self.button2 = tkinter.Button(master=self.privatekey_frame, text="Select филе", relief=tkinter.FLAT, command=self.add_private_key)

        self.ei_scrollbar = tkinter.Scrollbar(self.code_frame)
        self.eo_scrollbar = tkinter.Scrollbar(self.code_frame)
        self.di_scrollbar = tkinter.Scrollbar(self.code_frame)
        self.do_scrollbar = tkinter.Scrollbar(self.code_frame)
        self.encode_input = tkinter.Text(master=self.code_frame, bd=2, yscrollcommand=self.ei_scrollbar.set)
        self.encode_output = tkinter.Text(master=self.code_frame, bd=2, yscrollcommand=self.eo_scrollbar.set)
        self.button_encode = tkinter.Button(master=self.code_frame, bd=2, text="Encode", command=self.encode)
        self.decode_input = tkinter.Text(master=self.code_frame, bd=2, yscrollcommand=self.di_scrollbar.set)
        self.decode_output = tkinter.Text(master=self.code_frame, bd=2, yscrollcommand=self.do_scrollbar.set)
        self.button_decode = tkinter.Button(master=self.code_frame, bd=2, text="Decode", command=self.decode)
        self.ei_scrollbar.config(command=self.encode_input.yview)
        self.eo_scrollbar.config(command=self.encode_output.yview)
        self.di_scrollbar.config(command=self.decode_input.yview)
        self.do_scrollbar.config(command=self.decode_output.yview)

        self.pubkey_frame.grid(column=0, row=0, sticky="WESN")
        self.privatekey_frame.grid(column=1, row=0, sticky="WESN")
        self.code_frame.grid(column=0, row=1, columnspan=2, sticky="WESN")

        self.label1.grid(column=0, row=0, sticky="WESN")
        self.entry1.grid(column=1, row=0, sticky="WESN")
        self.button1.grid(column=2, row=0, sticky="WESN")
        self.label2.grid(column=0, row=0, sticky="WESN")
        self.entry2.grid(column=1, row=0, sticky="WESN")
        self.button2.grid(column=2, row=0, sticky="WESN")

        self.encode_input.grid(column=0, row=0, columnspan=2, rowspan=5, sticky="WESN")
        self.encode_output.grid(column=0, row=5, columnspan=2, rowspan=5, sticky="WESN")
        self.button_encode.grid(column=3, row=2, sticky="WESN")
        self.decode_input.grid(column=4, row=0, columnspan=2, rowspan=5, sticky="WESN")
        self.decode_output.grid(column=4, row=5, columnspan=2, rowspan=5, sticky="WESN")
        self.button_decode.grid(column=7, row=2, sticky="WESN")
        self.ei_scrollbar.grid(column=2, row=0, rowspan=5, sticky="WESN")
        self.eo_scrollbar.grid(column=2, row=5, rowspan=5, sticky="WESN")
        self.di_scrollbar.grid(column=6, row=2, rowspan=5, sticky="WESN")
        self.do_scrollbar.grid(column=6, row=0, rowspan=5, sticky="WESN")

        self.init_keys()





def main():
    App = Application()
    App.mainloop()


if __name__ == '__main__':
    main()


