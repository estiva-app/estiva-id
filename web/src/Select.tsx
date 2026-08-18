import { IconCheck, IconChevronDown } from '@tabler/icons-react'
import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'

/**
 * A select, drawn by this app rather than by the operating system.
 *
 * The native control cannot be styled where it matters: the option list is
 * rendered by the OS, so it arrives in the system font at the system size with
 * the system highlight colour, next to controls that are none of those things.
 *
 * Icons are `@tabler/icons-react` at Peek's sizing (16px, 1.5 stroke), which is
 * what every icon in this app uses now rather than a typed arrow glyph.
 *
 * The shape is Peek's menu, copied rather than invented - portal, `--bg-elevated`
 * on a `--border-default` outline, 8px radius, `--shadow-lg`, 4px of padding,
 * 36px rows that fill on hover. The trigger is the same control as `TextInput`,
 * which is what it sits beside.
 *
 * Replacing a native control means re-implementing what it gave away for free,
 * so the keyboard is not an afterthought here: arrows move, Home and End jump,
 * Enter and Space pick, Escape closes and returns focus to the trigger, and the
 * listbox is announced through `aria-activedescendant` rather than by moving
 * focus into the list. Type-ahead is the one native behaviour not reproduced.
 */
export interface SelectOption {
  value: string
  label: string
}

interface SelectProps {
  value: string
  onChange: (value: string) => void
  options: SelectOption[]
  /** Announced on the trigger when there is no visible <label> beside it. */
  ariaLabel?: string
  disabled?: boolean
}

export function Select({ value, onChange, options, ariaLabel, disabled }: SelectProps) {
  const id = useId()
  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const [rect, setRect] = useState<DOMRect | null>(null)
  const open = rect !== null

  const selectedIndex = useMemo(
    () =>
      Math.max(
        0,
        options.findIndex((o) => o.value === value),
      ),
    [options, value],
  )
  const [activeIndex, setActiveIndex] = useState(selectedIndex)

  const close = useCallback((refocus: boolean) => {
    setRect(null)
    if (refocus) triggerRef.current?.focus()
  }, [])

  const openMenu = useCallback(() => {
    setActiveIndex(selectedIndex)
    setRect(triggerRef.current?.getBoundingClientRect() ?? null)
  }, [selectedIndex])

  /**
   * Outside click and Escape, the same two exits every menu in the suite has.
   * `mousedown` rather than `click` so a press that starts outside dismisses
   * without also activating whatever it landed on.
   */
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (menuRef.current?.contains(e.target as Node)) return
      if (triggerRef.current?.contains(e.target as Node)) return
      setRect(null)
    }
    // A menu pinned to a rectangle has to go when the rectangle moves.
    const onMove = () => setRect(null)
    document.addEventListener('mousedown', onDown)
    window.addEventListener('resize', onMove)
    window.addEventListener('scroll', onMove, true)
    return () => {
      document.removeEventListener('mousedown', onDown)
      window.removeEventListener('resize', onMove)
      window.removeEventListener('scroll', onMove, true)
    }
  }, [open])

  const pick = (index: number) => {
    const option = options[index]
    if (!option) return
    onChange(option.value)
    close(true)
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!open) {
      // Down, Up, Enter and Space all open a closed native select.
      if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) {
        e.preventDefault()
        openMenu()
      }
      return
    }
    switch (e.key) {
      case 'Escape':
        e.preventDefault()
        close(true)
        break
      case 'ArrowDown':
        e.preventDefault()
        setActiveIndex((i) => Math.min(options.length - 1, i + 1))
        break
      case 'ArrowUp':
        e.preventDefault()
        setActiveIndex((i) => Math.max(0, i - 1))
        break
      case 'Home':
        e.preventDefault()
        setActiveIndex(0)
        break
      case 'End':
        e.preventDefault()
        setActiveIndex(options.length - 1)
        break
      case 'Enter':
      case ' ':
        e.preventDefault()
        pick(activeIndex)
        break
      case 'Tab':
        close(false)
        break
    }
  }

  const selected = options.find((o) => o.value === value)

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        className="select-trigger"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={ariaLabel}
        onClick={() => (open ? close(false) : openMenu())}
        onKeyDown={onKeyDown}
      >
        <span className="select-value">{selected?.label ?? ''}</span>
        <IconChevronDown size={16} stroke={1.5} className="select-chevron" />
      </button>

      {open &&
        rect &&
        createPortal(
          <div
            ref={menuRef}
            className="menu"
            // biome-ignore lint/a11y/useSemanticElements: a native <select> is exactly what this replaces - its option list is drawn by the OS and cannot be styled, which is why this component exists.
            role="listbox"
            aria-activedescendant={`${id}-${activeIndex}`}
            tabIndex={-1}
            style={{ top: rect.bottom + 4, left: rect.left, minWidth: rect.width }}
          >
            {options.map((option, index) => (
              // biome-ignore lint/a11y/useFocusableInteractive: required by this pattern - focus stays on the trigger and the active option is published via aria-activedescendant. Focusable options would move focus into the list and break that.
              <div
                key={option.value}
                id={`${id}-${index}`}
                // biome-ignore lint/a11y/useSemanticElements: standing in for a native <option>, see above.
                role="option"
                aria-selected={option.value === value}
                className={[
                  'menu-item',
                  index === activeIndex ? 'is-active' : '',
                  option.value === value ? 'is-selected' : '',
                ]
                  .filter(Boolean)
                  .join(' ')}
                onMouseEnter={() => setActiveIndex(index)}
                onMouseDown={(e) => {
                  // The document-level dismiss also listens on mousedown.
                  e.preventDefault()
                  pick(index)
                }}
              >
                <span>{option.label}</span>
                {option.value === value && (
                  <IconCheck size={16} stroke={1.5} className="menu-check" />
                )}
              </div>
            ))}
          </div>,
          document.body,
        )}
    </>
  )
}
