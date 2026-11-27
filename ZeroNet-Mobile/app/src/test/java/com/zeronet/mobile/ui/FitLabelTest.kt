package com.zeronet.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.dp
import com.zeronet.mobile.ui.components.PrimaryButton
import com.zeronet.mobile.ui.components.Segmented
import com.zeronet.mobile.ui.components.TonalButton
import com.zeronet.mobile.ui.theme.ZeroTheme
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * On a small phone, labels on tabs and buttons shrink to fit instead of
 * ending in "…" (`FitLabel`). 320 dp is the narrowest common phone width,
 * and the larger font scale stands in for users who set big text.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w320dp-h640dp-xhdpi", fontScale = 1.15f)
class FitLabelTest {

    @get:Rule
    val compose = createComposeRule()

    private fun ellipsized(text: String): Boolean {
        val node = compose.onNodeWithText(text).fetchSemanticsNode()
        val results = mutableListOf<TextLayoutResult>()
        node.config.getOrNull(SemanticsActions.GetTextLayoutResult)?.action?.invoke(results)
        val layout = results.single()
        return (0 until layout.lineCount).any { layout.isLineEllipsized(it) } || layout.hasVisualOverflow
    }

    @Test
    fun tabs_and_buttons_on_a_small_phone_are_not_cut_short() {
        compose.setContent {
            ZeroTheme {
                Column(Modifier.fillMaxWidth().padding(16.dp)) {
                    Segmented(listOf("Recommended", "Countries", "Mine"), "Recommended", {}, label = { it })
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        TonalButton("Remind me later", {}, Modifier.weight(1f))
                        PrimaryButton("Update now", {}, Modifier.weight(1.4f))
                    }
                }
            }
        }
        for (label in listOf("Recommended", "Countries", "Mine", "Remind me later", "Update now")) {
            assertFalse("\"$label\" was cut short", ellipsized(label))
        }
    }
}
