#include "tosaithe-util.h"

#include <uefi-devicepath.h>
#include <uefi-media-file.h>

extern EFI_SYSTEM_TABLE *EST;

EFI_FILE_PROTOCOL *open_file(const EFI_DEVICE_PATH_PROTOCOL *dev_path)
{
    EFI_DEVICE_PATH_PROTOCOL *file_devpath = const_cast<EFI_DEVICE_PATH_PROTOCOL *>(dev_path);
    EFI_HANDLE load_dev_hndl;
    EFI_STATUS status = EBS->LocateDevicePath(&EFI_simple_file_system_protocol_guid, &file_devpath,
            &load_dev_hndl);
    if (EFI_ERROR(status)) {
        throw open_file_exception(open_file_exception::NO_FSPROTOCOL_FOR_DEV_PATH, status);
    }

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfs_protocol = nullptr;

    status = EBS->HandleProtocol(load_dev_hndl, &EFI_simple_file_system_protocol_guid,
            (void **)&sfs_protocol);
    if (EFI_ERROR(status) || sfs_protocol == nullptr) {
        // This shouldn't happen; firmware is misbehaving?
        throw open_file_exception(open_file_exception::NO_FSPROTOCOL_FOR_DEV_PATH, status);
    }

    EFI_FILE_PROTOCOL *fs_root = nullptr;
    status = sfs_protocol->OpenVolume(sfs_protocol, &fs_root);
    if (EFI_ERROR(status) || fs_root == nullptr) {
        throw open_file_exception(open_file_exception::CANNOT_OPEN_VOLUME, status);
    }

    // Need to convert remaining path to string path (within filesystem)
    EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *dp2text_proto =
            (EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *)locate_protocol(EFI_device_path_to_text_protocol_guid);

    if (dp2text_proto == nullptr) {
        // TODO combine the path ourselves
        fs_root->Close(fs_root);
        throw open_file_exception(open_file_exception::NO_DPTT_PROTOCOL);
    }

    EFI_FILE_PROTOCOL *file_to_load = nullptr;

    {
        CHAR16 *file_path = dp2text_proto->ConvertDevicePathToText(file_devpath,
                false /* displayOnly */, false /* allowShortcuts */);

        if (file_path == nullptr) {
            fs_root->Close(fs_root);
            throw std::bad_alloc();
        }

        status = fs_root->Open(fs_root, &file_to_load, file_path, EFI_FILE_MODE_READ, 0);

        free_pool(file_path);
        fs_root->Close(fs_root);

        if (EFI_ERROR(status) || file_to_load == nullptr) {
            throw open_file_exception(open_file_exception::CANNOT_OPEN_FILE, status);
        }
    }

    return file_to_load;
}

EFI_GRAPHICS_OUTPUT_PROTOCOL *find_GOP()
{
    // First try looking up via ConOut handle:
    {
        void *gop_proto = nullptr;
        EFI_STATUS status = EBS->HandleProtocol(&EST->ConsoleOutHandle,
                &EFI_graphics_output_protocol_guid, &gop_proto);
        if (status == EFI_SUCCESS) {
            return (EFI_GRAPHICS_OUTPUT_PROTOCOL *)gop_proto;
        }
    }

    UINTN conout_var_size = 0;
    EFI_STATUS status = EST->RuntimeServices->GetVariable(L"ConOutDev", &EFI_global_variable_guid,
            nullptr, &conout_var_size, nullptr);
    if (EFI_ERROR(status) && status != EFI_BUFFER_TOO_SMALL)
        goto fallback_locate;

    {
        std::unique_ptr<void> conout_var_val { alloc_pool(conout_var_size) };
        status = EST->RuntimeServices->GetVariable(L"ConOutDev", &EFI_global_variable_guid, nullptr,
                &conout_var_size, conout_var_val.get());
        if (EFI_ERROR(status))
            goto fallback_locate;

        EFI_HANDLE gop_hndl = nullptr;
        EFI_DEVICE_PATH_PROTOCOL *con_out_devpath = (EFI_DEVICE_PATH_PROTOCOL *)conout_var_val.get();

        while (true) {
            status = EBS->LocateDevicePath(&EFI_graphics_output_protocol_guid, &con_out_devpath, &gop_hndl);
            if (status == EFI_SUCCESS) {
                void *gop_proto = nullptr;
                EBS->HandleProtocol(gop_hndl, &EFI_graphics_output_protocol_guid, &gop_proto);
                // (^^ Shouldn't fail, but if it does, we'll return null anyway)
                return (EFI_GRAPHICS_OUTPUT_PROTOCOL *)gop_proto;
            }

            con_out_devpath = find_next_devpath_instance(con_out_devpath);
        }
    }

    fallback_locate:

    // fall back to locate_protocol:
    return (EFI_GRAPHICS_OUTPUT_PROTOCOL *) locate_protocol(EFI_graphics_output_protocol_guid);;
}
