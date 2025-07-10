use ferrisetw::provider::Provider;
use windows::core::GUID;

pub struct SecurityProviders;

impl SecurityProviders {
    pub fn microsoft_windows_security_auditing() -> Provider {
        Provider::by_guid(
            &GUID::from_values(
                0x54849625,
                0x5478,
                0x4994,
                [0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d],
            )
        )
    }

    pub fn microsoft_windows_kernel_process() -> Provider {
        Provider::by_guid(
            &GUID::from_values(
                0x22fb2cd6,
                0x0e7b,
                0x422b,
                [0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16],
            )
        )
    }

    pub fn microsoft_windows_kernel_network() -> Provider {
        Provider::by_guid(
            &GUID::from_values(
                0x7dd42a49,
                0x5329,
                0x4832,
                [0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88],
            )
        )
    }

    pub fn microsoft_windows_kernel_file() -> Provider {
        Provider::by_guid(
            &GUID::from_values(
                0xedd08927,
                0x9cc4,
                0x4e65,
                [0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89],
            )
        )
    }

    pub fn microsoft_windows_threat_intelligence() -> Provider {
        Provider::by_guid(
            &GUID::from_values(
                0xf4e1897c,
                0xbb5d,
                0x5668,
                [0xf1, 0xb8, 0xdf, 0xdd, 0xed, 0x3b, 0x62, 0xfb],
            )
        )
    }

    pub fn microsoft_windows_dns_client() -> Provider {
        Provider::by_guid(
            &GUID::from_values(
                0x1c95126e,
                0x7eea,
                0x49a9,
                [0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d],
            )
        )
    }

    pub fn microsoft_windows_powershell() -> Provider {
        Provider::by_guid(
            &GUID::from_values(
                0xa0c1853b,
                0x5c40,
                0x4b15,
                [0x87, 0x66, 0x3c, 0xf1, 0xc5, 0x8f, 0x98, 0x5a],
            )
        )
    }

    pub fn microsoft_windows_wmi_activity() -> Provider {
        Provider::by_guid(
            &GUID::from_values(
                0x1418ef04,
                0xb0b4,
                0x4623,
                [0xbf, 0x7e, 0xd7, 0x4a, 0xb8, 0xdb, 0x01, 0x11],
            )
        )
    }
}