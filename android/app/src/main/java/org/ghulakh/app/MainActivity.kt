package org.ghulakh.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            )
        }

        root.addView(TextView(this).apply {
            text = "ГӀулакх"
            textSize = 28f
        })
        root.addView(TextView(this).apply {
            text = "Ghulakh"
            textSize = 16f
        })
        root.addView(TextView(this).apply {
            text = "Исследовательская сборка · 0.1.0"
            textSize = 14f
        })

        status = TextView(this).apply {
            text = "Транспорт ещё не подключён. Эта сборка не маршрутизирует трафик."
            textSize = 16f
            setPadding(0, 32, 0, 16)
        }
        root.addView(status)

        root.addView(Button(this).apply {
            text = "Запросить разрешение VPN"
            setOnClickListener { requestVpnPermission() }
        })

        setContentView(root)
    }

    private fun requestVpnPermission() {
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent == null) {
            status.text = "Разрешение VPN уже выдано. Транспорт ещё не подключён; трафик не маршрутизируется."
        } else {
            @Suppress("DEPRECATION")
            startActivityForResult(permissionIntent, REQUEST_VPN_PERMISSION)
        }
    }

    @Deprecated("Deprecated by Android; retained for compatibility with the current minimal Activity")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_PERMISSION) {
            status.text = if (resultCode == RESULT_OK) {
                "Разрешение VPN выдано. Туннель пока не активируется: транспорт находится в разработке."
            } else {
                "Разрешение VPN не выдано. Подключение не выполнялось."
            }
        }
    }

    private companion object {
        const val REQUEST_VPN_PERMISSION = 1001
    }
}
