from scanner import get_model
if __name__ == "__main__":
    model = get_model()
    print("MailGuard text model loaded/trained successfully.")
    print("Classes:", list(model.classes_))
