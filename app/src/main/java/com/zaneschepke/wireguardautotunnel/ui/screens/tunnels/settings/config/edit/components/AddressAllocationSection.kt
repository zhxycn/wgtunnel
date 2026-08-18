package com.zaneschepke.wireguardautotunnel.ui.screens.tunnels.settings.config.edit.components

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.intl.Locale
import com.zaneschepke.wireguardautotunnel.R
import com.zaneschepke.wireguardautotunnel.ui.common.textbox.ConfigurationTextBox

@Composable
fun AddressAllocationSection(prefixes: String, onPrefixesChange: (String) -> Unit) {
    ConfigurationTextBox(
        value = prefixes,
        onValueChange = onPrefixesChange,
        label = stringResource(R.string.address_prefixes),
        hint =
            stringResource(R.string.hint_template, stringResource(R.string.comma_separated))
                .lowercase(locale = Locale.current.platformLocale),
        modifier = Modifier.fillMaxWidth(),
    )
}
