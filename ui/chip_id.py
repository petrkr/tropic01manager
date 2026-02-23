from __future__ import annotations

from PyQt6 import QtWidgets


def setup_chip_id(window, get_ts):
    def refresh_chip_id(chip_id=None):
        ts = get_ts()
        if chip_id is None and not ts:
            return

        try:
            if chip_id is None:
                chip_id = ts.chipid

            window.lblChipIDVersion.setText('.'.join(map(str, chip_id.chip_id_version)))
            window.lblSiliconRev.setText(chip_id.silicon_rev)
            window.lblPackageType.setText(f"{chip_id.package_type_name} (0x{chip_id.package_type_id:04X})")
            window.lblFabrication.setText(f"{chip_id.fab_name} (0x{chip_id.fab_id:03X})")
            window.lblPartNumberID.setText(f"0x{chip_id.part_number_id:03X}")
            window.lblHSMVersion.setText('.'.join(map(str, chip_id.hsm_version)))
            window.lblProgVersion.setText('.'.join(map(str, chip_id.prog_version)))
            window.lblBatchID.setText(chip_id.batch_id.hex())

            try:
                part_num_ascii = chip_id.part_num_data.decode('ascii', 'ignore').rstrip('\x00')
                if part_num_ascii:
                    window.lblPartNumberASCII.setText(part_num_ascii)
                else:
                    window.lblPartNumberASCII.setText(f"(hex: {chip_id.part_num_data.hex()})")
            except Exception:
                window.lblPartNumberASCII.setText(f"(hex: {chip_id.part_num_data.hex()})")

            sn = chip_id.serial_number
            window.lblSerialNumber.setText(f"0x{sn.sn:02X}")
            window.lblSNFabID.setText(f"0x{sn.fab_id:03X}")
            window.lblSNPartNumber.setText(f"0x{sn.part_number_id:03X}")
            window.lblLotID.setText(sn.lot_id.hex())
            window.lblWaferID.setText(f"0x{sn.wafer_id:02X}")
            window.lblWaferCoords.setText(f"({sn.x_coord}, {sn.y_coord})")
        except Exception as e:
            QtWidgets.QMessageBox.critical(window, "Error", f"Failed to get chip ID:\n{str(e)}")

    return refresh_chip_id
